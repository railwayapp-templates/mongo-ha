//! Credential pin: the root password and the keyfile this volume actually
//! runs with, persisted on the volume, so an edit of the environment can
//! never silently lock the wrapper out of its own mongod or split the set.
//!
//! ## The two couplings this breaks
//! - The wrapper authenticates its own admin commands with
//!   `MONGO_INITDB_ROOT_PASSWORD`. That variable only ever *initializes* the
//!   root user (on an empty data dir); editing it later changes nothing in
//!   mongod, so from the next boot on the wrapper would be knocking with the
//!   wrong password — `/role` 503 everywhere, no orchestration — while mongod
//!   is perfectly healthy. mysql-ha closed the same hole with its password
//!   pin; this is the MongoDB port.
//! - The keyfile is derived from `RS_KEY`, which the template stamps as a
//!   reference to that same password. A re-derived keyfile on one member and
//!   not the others means members refuse each other's heartbeats: a redeploy
//!   after a password edit would take the set apart one node at a time.
//!
//! ## Rules
//! - The pin is written once the environment's password has been PROVEN
//!   against the live mongod (fresh volume: the entrypoint just created the
//!   root user with it; adopted volume: it is the account the standalone ran
//!   with). Never pinned unproven — and in HA mode never before this node is
//!   a PRIMARY or SECONDARY of its set: a joiner's mongod holds a root user
//!   initial sync is about to replace with the set's, so a proof against it
//!   proves nothing about the set (see `pin_allowed`).
//! - On boot, a pin outranks the environment for BOTH values. Disagreement is
//!   logged loudly and reported, once per boot.
//! - The resolver keeps probing the environment's password while it
//!   disagrees with the pin. The moment it authenticates — the user rotated
//!   the stored user properly, then updated the variable — the pin adopts it.
//!   The keyfile pin never follows: rotating a keyfile is a coordinated,
//!   set-wide operation this version does not perform.
//! - A node with no pin (fresh volume, first HA boot) that finds a live set
//!   among its peers adopts THAT set's keyfile over `/rs/keyfile` (proving
//!   the root password to the peer) instead of deriving its own — so a
//!   scale-up or a wiped-volume rejoin after an RS_KEY-only edit still joins.
//!   A settled member refusing the root password stops the node before mongod
//!   spawns, with the fix in its log (rs::discover_live_set_keyfile): a
//!   keyfile derived from the edited RS_KEY would never be accepted, and
//!   nothing is pinned.

use crate::keyfile::derive_keyfile_content;
use crate::mongo::{Hello, Mongo, PasswordProbe};
use anyhow::{Context, Result};
use common::{Telemetry, TelemetryEvent};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

pub const PIN_FILE: &str = ".railway-mongo-auth-pin";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthPin {
    /// The root password mongod actually enforces.
    pub password: String,
    /// The keyfile content every member of this node's set shares. None on a
    /// volume that has only ever run standalone.
    #[serde(default)]
    pub keyfile: Option<String>,
}

fn pin_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join(PIN_FILE)
}

/// The pin on this volume, if it holds one that parses. A torn or garbage
/// file reads as absent (warned by the caller): the environment then applies,
/// which is exactly the pre-pin behavior, and the next proof rewrites it.
pub fn read_pin(data_dir: &str) -> Option<AuthPin> {
    let raw = fs::read_to_string(pin_path(data_dir)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Persist the pin atomically (temp file + rename), owner-only readable.
pub fn write_pin(data_dir: &str, pin: &AuthPin) -> Result<()> {
    let path = pin_path(data_dir);
    let tmp = path.with_extension("tmp");
    let body = serde_json::to_string(pin).context("serializing the auth pin")?;
    fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

/// What this boot should run with, resolved from the pin and the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootCredentials {
    pub password: String,
    /// None in standalone mode (no RS_KEY, nothing to derive from).
    pub keyfile: Option<String>,
    /// True when the environment disagrees with the pin on either value —
    /// the caller logs and reports it.
    pub env_drifted: bool,
}

/// Resolve the credentials for this boot.
///
/// `pin` — what the volume remembers (None on a fresh volume or first HA
/// boot). `env_password` / `env_rs_key` — the environment. `live_set_keyfile`
/// — a keyfile fetched from a peer that already holds a set, when this node
/// has no pin (see the module doc); ignored when a pin exists, because a
/// pinned member IS one of the set's holders.
pub fn resolve_boot_credentials(
    pin: Option<&AuthPin>,
    env_password: &str,
    env_rs_key: Option<&str>,
    live_set_keyfile: Option<&str>,
) -> BootCredentials {
    let env_keyfile = env_rs_key.map(derive_keyfile_content);
    match pin {
        Some(pin) => {
            // A pinned keyfile outranks the environment; a pin with no
            // keyfile (standalone history) resolves the keyfile like a fresh
            // node would.
            let keyfile = pin
                .keyfile
                .clone()
                .or_else(|| live_set_keyfile.map(str::to_string))
                .or_else(|| env_keyfile.clone());
            let keyfile_drifted = matches!(
                (&pin.keyfile, &env_keyfile),
                (Some(pinned), Some(env)) if pinned != env
            );
            BootCredentials {
                env_drifted: pin.password != env_password || keyfile_drifted,
                password: pin.password.clone(),
                keyfile,
            }
        }
        None => BootCredentials {
            password: env_password.to_string(),
            keyfile: live_set_keyfile.map(str::to_string).or(env_keyfile),
            env_drifted: false,
        },
    }
}

/// How often the resolver re-probes while something is still unproven or
/// the environment still disagrees with the pin.
const RESOLVE_INTERVAL: Duration = Duration::from_secs(30);

/// Whether a `Works` verdict taken against this node's mongod may be pinned.
/// Standalone: always — the local root user is the only one there is. HA:
/// only once the node is a PRIMARY or SECONDARY of its set. Before that the
/// server that answered is docker-entrypoint's init server or a joiner's
/// pre-sync mongod, whose root user initial sync replaces with the set's: a
/// proof against it proves nothing about the set, and pinning it would lock
/// the wrapper out of its own node once the sync lands — or, on a drifted
/// joiner, pin the edited values for good.
pub fn pin_allowed(rs_enabled: bool, hello: Option<&Hello>) -> bool {
    !rs_enabled || hello.is_some_and(Hello::is_settled_member)
}

/// Prove the boot credentials against the live mongod and keep the pin
/// truthful for the rest of the process:
///
/// 1. The active password (the pin's, or the environment's on a fresh
///    volume) is probed until mongod answers; on `Works` the pin is written
///    (password + this boot's keyfile) if it does not already say so — in HA
///    mode only once the node is a PRIMARY or SECONDARY (`pin_allowed`); the
///    probe repeats until then, so the pinned proof is one taken against the
///    set's own root user, never a joiner's pre-sync one.
/// 2. While the environment's password differs from the active one, it is
///    probed too. `Works` means the user rotated the stored user and then
///    updated the variable: the pool swaps to it and the pin adopts it (the
///    pin under the same membership rule). `AccessDenied` is the ordinary
///    "variable edited, user not rotated" drift: warned once, and the pinned
///    password stays in force.
///
/// Returns once the pin is written from a valid proof and nothing disagrees
/// — an edit made after that reaches a NEW process (the redeploy), which
/// starts its own resolver.
pub async fn resolver(
    data_dir: String,
    env_password: String,
    boot: BootCredentials,
    mongo: Mongo,
    telemetry: Arc<Telemetry>,
    rs_enabled: bool,
) {
    let mut active = boot.password.clone();
    let mut proven = false;
    let mut pinned = false;
    let mut drift_reported = false;
    let mut membership_wait_logged = false;
    let write = |password: &str| -> bool {
        let pin = AuthPin {
            password: password.to_string(),
            keyfile: boot.keyfile.clone(),
        };
        if read_pin(&data_dir).as_ref() == Some(&pin) {
            return true;
        }
        match write_pin(&data_dir, &pin) {
            Ok(()) => {
                info!("credential pin written");
                true
            }
            Err(e) => {
                error!(error = %format!("{e:#}"), "could not write the credential pin");
                false
            }
        }
    };
    loop {
        if !proven || !pinned {
            let (verdict, hello) = mongo.probe_local_password_hello(&active).await;
            match verdict {
                PasswordProbe::Works => {
                    proven = true;
                    if pin_allowed(rs_enabled, hello.as_ref()) {
                        pinned = write(&active);
                    } else if !membership_wait_logged {
                        membership_wait_logged = true;
                        info!("root password proven against this node's mongod, but the node is not a PRIMARY or SECONDARY of the set yet; the pin waits for membership (initial sync replaces a joiner's local root user)");
                    }
                }
                PasswordProbe::AccessDenied => {
                    // The password this node runs with no longer works and
                    // the environment's is the same string: nothing left to
                    // try. Loud, and keep probing — a proper rotation shows
                    // up as the environment probe below succeeding.
                    if !drift_reported {
                        drift_reported = true;
                        let error = "the root password this node runs with is refused by mongod and MONGO_INITDB_ROOT_PASSWORD carries no working alternative; the wrapper cannot run admin commands until the stored user matches one of them"
                            .to_string();
                        error!("{error}");
                        telemetry.send(TelemetryEvent::ComponentError {
                            component: "mongo-wrapper".to_string(),
                            error,
                            context: "credential-pin".to_string(),
                        });
                    }
                }
                PasswordProbe::NotReady(_) => {}
            }
        }

        if env_password != active {
            let (verdict, hello) = mongo.probe_local_password_hello(&env_password).await;
            match verdict {
                PasswordProbe::Works => {
                    info!("MONGO_INITDB_ROOT_PASSWORD authenticates: the stored user was rotated; adopting it");
                    mongo.swap_password(&env_password).await;
                    active = env_password.clone();
                    proven = true;
                    drift_reported = false;
                    // Same membership rule for the pin; the pool swap itself
                    // is immediate — a password mongod accepts beats one it
                    // refuses, whatever state the node is in.
                    pinned = pin_allowed(rs_enabled, hello.as_ref()) && write(&active);
                }
                PasswordProbe::AccessDenied => {
                    if !drift_reported {
                        drift_reported = true;
                        let error = "MONGO_INITDB_ROOT_PASSWORD differs from the password mongod enforces; the variable only initializes a fresh data dir, so the wrapper keeps using the pinned password. Rotate the stored user (db.changeUserPassword) before or after the edit, and note the keyfile (RS_KEY) never follows an edit: new members adopt the live set's keyfile from a peer instead"
                            .to_string();
                        warn!("{error}");
                        telemetry.send(TelemetryEvent::ComponentError {
                            component: "mongo-wrapper".to_string(),
                            error,
                            context: "credential-drift".to_string(),
                        });
                    }
                }
                PasswordProbe::NotReady(_) => {}
            }
        } else if proven && pinned {
            return;
        }

        tokio::time::sleep(RESOLVE_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_pin_derives_from_the_environment() {
        let c = resolve_boot_credentials(None, "pw", Some("key"), None);
        assert_eq!(c.password, "pw");
        assert_eq!(
            c.keyfile.as_deref(),
            Some(derive_keyfile_content("key").as_str())
        );
        assert!(!c.env_drifted);
        let standalone = resolve_boot_credentials(None, "pw", None, None);
        assert_eq!(standalone.keyfile, None);
    }

    #[test]
    fn no_pin_prefers_the_live_sets_keyfile() {
        let c = resolve_boot_credentials(None, "pw", Some("key"), Some("LIVEKEYFILE=="));
        assert_eq!(c.keyfile.as_deref(), Some("LIVEKEYFILE=="));
        assert_eq!(c.password, "pw");
    }

    #[test]
    fn a_pin_outranks_the_environment_and_flags_drift() {
        let pin = AuthPin {
            password: "old".into(),
            keyfile: Some(derive_keyfile_content("old")),
        };
        let same = resolve_boot_credentials(Some(&pin), "old", Some("old"), Some("ignored"));
        assert_eq!(same.password, "old");
        assert_eq!(same.keyfile, pin.keyfile);
        assert!(!same.env_drifted);

        let drifted = resolve_boot_credentials(Some(&pin), "new", Some("new"), None);
        assert_eq!(
            drifted.password, "old",
            "the pinned password keeps the wrapper in"
        );
        assert_eq!(
            drifted.keyfile, pin.keyfile,
            "the keyfile never follows the environment"
        );
        assert!(drifted.env_drifted);
    }

    #[test]
    fn a_standalone_pin_resolves_the_keyfile_like_a_fresh_node() {
        // A volume that only ever ran standalone pins its password but no
        // keyfile; on its first HA boot (a conversion) the keyfile comes from
        // a live set if one exists, else from the environment — and that is
        // not drift.
        let pin = AuthPin {
            password: "pw".into(),
            keyfile: None,
        };
        let c = resolve_boot_credentials(Some(&pin), "pw", Some("key"), None);
        assert_eq!(
            c.keyfile.as_deref(),
            Some(derive_keyfile_content("key").as_str())
        );
        assert!(!c.env_drifted);
        let c = resolve_boot_credentials(Some(&pin), "pw", Some("key"), Some("LIVE=="));
        assert_eq!(c.keyfile.as_deref(), Some("LIVE=="));
    }

    #[test]
    fn the_pin_waits_for_membership_in_ha_mode_only() {
        let primary = Hello {
            is_writable_primary: true,
            set_name: Some("rs0".into()),
            ..Default::default()
        };
        let secondary = Hello {
            secondary: true,
            set_name: Some("rs0".into()),
            ..Default::default()
        };
        // STARTUP2: the set is named, the node is neither role.
        let syncing = Hello {
            set_name: Some("rs0".into()),
            ..Default::default()
        };
        // docker-entrypoint's init server, or --replSet with no config yet.
        let init_server = Hello {
            is_writable_primary: true,
            ..Default::default()
        };
        let uninitiated = Hello {
            isreplicaset: true,
            ..Default::default()
        };
        assert!(pin_allowed(true, Some(&primary)));
        assert!(pin_allowed(true, Some(&secondary)));
        assert!(!pin_allowed(true, Some(&syncing)));
        assert!(!pin_allowed(true, Some(&init_server)));
        assert!(!pin_allowed(true, Some(&uninitiated)));
        assert!(!pin_allowed(true, None));
        // Standalone: the local root user is the only one there is.
        assert!(pin_allowed(false, Some(&init_server)));
        assert!(pin_allowed(false, None));
    }

    #[test]
    fn pin_round_trips_through_the_volume_and_tolerates_garbage() {
        let dir = std::env::temp_dir().join(format!("mongo-auth-pin-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let d = dir.to_str().unwrap();
        assert!(read_pin(d).is_none());
        let pin = AuthPin {
            password: "pw".into(),
            keyfile: Some("K==".into()),
        };
        write_pin(d, &pin).unwrap();
        assert_eq!(read_pin(d), Some(pin));
        let mode = fs::metadata(pin_path(d)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::write(pin_path(d), "not json").unwrap();
        assert!(read_pin(d).is_none());
        fs::remove_dir_all(&dir).ok();
    }
}
