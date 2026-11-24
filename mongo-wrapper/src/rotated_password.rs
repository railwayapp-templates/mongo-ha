//! A member that was not running while the set rotated its password.
//!
//! The control plane rotates credentials on the members that are running. A
//! member whose container was down takes part in no step: its volume pins the
//! previous root password and keyfile, and it comes back with
//! MONGO_INITDB_ROOT_PASSWORD (and RS_KEY, a reference to it on the template)
//! already on the new password. The pin keeps it on the previous credentials,
//! which is right for an edited variable and wrong here: the set runs on the
//! new keyfile only and refuses the previous password.
//!
//! The set says which case it is. A live peer hands its keyfile only to a
//! caller that proves the root password against the peer's own mongod
//! (`/rs/keyfile`). When it accepts the variable's password, the set rotated
//! while this member was away: the member presents that password to the set
//! from then on (re-adding itself if it was pruned meanwhile) and restarts
//! mongod on the set's keyfile when it booted on another one. The new
//! password reaches the member's own users through replication; the
//! resolver in auth_pin then moves the pool and the pin to it. An edited
//! variable is refused by the set and changes nothing.

use crate::auth_pin::{read_pin, write_pin};
use crate::config::Config;
use crate::credentials::{keys_overlap, loaded_keyfile, RESTART_MONGO};
use crate::mongo::{states, Mongo, RsStatus};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

/// The variable's password, once a live peer proved the set runs with it.
static ADOPTED: Mutex<Option<String>> = Mutex::new(None);
const SECONDARY: i32 = 2;
const ASK_INTERVAL: Duration = Duration::from_secs(10);
/// After no peer handed its keyfile out (none answered, or each refused the
/// variable's password). Only a member cut off from the set asks at all, so
/// an edited variable on a working member costs the set nothing.
const ASK_AGAIN: Duration = Duration::from_secs(30);

/// The password this member presents to the set when the set proved it
/// rotated while the member was away; `None` otherwise.
pub fn adopted() -> Option<String> {
    ADOPTED.lock().unwrap().clone()
}

/// The adopted password while the pin still holds another one. Once the pin
/// reaches it (the resolver followed the replicated users), the pin speaks
/// for the member again, so a later rotation that moves the pin is followed.
pub fn adopted_over_pin(pin_password: Option<&str>) -> Option<String> {
    let mut adopted = ADOPTED.lock().unwrap();
    if adopted.is_some() && adopted.as_deref() == pin_password {
        *adopted = None;
    }
    adopted.clone()
}

/// Record that a live peer accepted the variable's password (the boot's
/// keyfile reconciliation found it so).
pub fn note_adopted(password: &str) {
    let mut adopted = ADOPTED.lock().unwrap();
    if adopted.as_deref() != Some(password) {
        info!(
            "a live member accepts the password in MONGO_INITDB_ROOT_PASSWORD: the set rotated \
             while this member was away. Presenting the new password to the set"
        );
        *adopted = Some(password.to_string());
    }
}

/// Whether this member works with the set as it is: it is a healthy
/// PRIMARY or SECONDARY and sees a healthy primary.
fn in_a_working_set(status: &RsStatus) -> bool {
    let RsStatus::Active {
        my_state, members, ..
    } = status
    else {
        return false;
    };
    matches!(*my_state, states::PRIMARY | SECONDARY)
        && members
            .iter()
            .any(|m| m.state == states::PRIMARY && m.healthy)
}

/// Keeps asking the set while this member's pin differs from the variable,
/// no rotation is staged on it and it is cut off from the set. Started once
/// per boot in replica set mode.
pub async fn adopt_rotated_password(config: Arc<Config>, mongo: Mongo) {
    let variable = config.mongo_root_password.clone();
    let mut wait = ASK_INTERVAL;
    loop {
        tokio::time::sleep(wait).await;
        wait = ASK_INTERVAL;
        let Some(mut pin) = read_pin(&config.data_dir) else {
            continue;
        };
        if pin.password == variable {
            return;
        }
        if std::path::Path::new(&format!("{}/.railway_rotation", config.data_dir)).exists() {
            continue;
        }
        if adopted().as_deref() == Some(variable.as_str()) {
            return;
        }
        if mongo
            .rs_status()
            .await
            .is_ok_and(|status| in_a_working_set(&status))
        {
            continue;
        }
        let Some(keyfile) =
            crate::rs::discover_live_set_keyfile_with_password(&config, &variable).await
        else {
            wait = ASK_AGAIN;
            continue;
        };
        note_adopted(&variable);
        if loaded_keyfile().is_some_and(|loaded| keys_overlap(&loaded, &keyfile)) {
            return;
        }
        pin.keyfile = Some(keyfile);
        if let Err(e) = write_pin(&config.data_dir, &pin) {
            warn!(error = %format!("{e:#}"), "could not record the set's keyfile; retrying");
            continue;
        }
        info!("restarting mongod on the set's keyfile");
        RESTART_MONGO.notify_one();
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mongo::RsMember;

    fn member(state: i32, healthy: bool, is_self: bool) -> RsMember {
        RsMember {
            id: 0,
            host: "h:27017".into(),
            state,
            state_str: String::new(),
            healthy,
            is_self,
            optime_secs: None,
        }
    }
    fn status(my_state: i32, members: Vec<RsMember>) -> RsStatus {
        RsStatus::Active {
            set_name: "rs0".into(),
            my_state,
            my_state_str: String::new(),
            members,
            voting_members: None,
        }
    }

    #[test]
    fn the_pin_speaks_again_once_it_reaches_the_adopted_password() {
        *ADOPTED.lock().unwrap() = Some("new".into());
        assert_eq!(adopted_over_pin(Some("old")).as_deref(), Some("new"));
        assert_eq!(adopted_over_pin(Some("new")), None);
        // A later rotation moves the pin; nothing stale outranks it.
        assert_eq!(adopted_over_pin(Some("newer")), None);
    }

    #[test]
    fn only_a_member_cut_off_from_the_set_asks_about_its_credentials() {
        // A secondary that sees its primary works with what it holds: an
        // edited variable there is an edit.
        assert!(in_a_working_set(&status(
            SECONDARY,
            vec![
                member(SECONDARY, true, true),
                member(states::PRIMARY, true, false)
            ]
        )));
        // The member that came back on a keyfile the set no longer runs:
        // nothing it can reach is a primary.
        assert!(!in_a_working_set(&status(
            SECONDARY,
            vec![
                member(SECONDARY, true, true),
                member(states::PRIMARY, false, false)
            ]
        )));
        // REMOVED: pruned from the config while away.
        assert!(!in_a_working_set(&status(10, vec![])));
        assert!(!in_a_working_set(&RsStatus::NotAMember));
        assert!(!in_a_working_set(&RsStatus::NotInitialized));
    }
}
