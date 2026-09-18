//! Authenticated, retryable phases of the platform's cluster rotation.
//! Keyfiles change in two ordered rolling passes: both keys, then target
//! only. A lost HTTP response can safely repeat every phase.
use crate::auth_pin::{read_pin, write_pin, AuthPin};
use crate::health_server::AppState;
use crate::mongo::PasswordProbe;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    Json,
};
use base64::Engine;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

static ROTATION: Mutex<()> = Mutex::const_new(());
pub static RESTART_MONGO: tokio::sync::Notify = tokio::sync::Notify::const_new();
static LOADED_KEYFILE: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);
pub fn loaded_keyfile() -> Option<String> {
    LOADED_KEYFILE.read().unwrap().clone()
}
pub fn set_loaded_keyfile(keyfile: String) {
    *LOADED_KEYFILE.write().unwrap() = Some(keyfile);
}
fn target_keyfile(request: &Rotation, overlap: bool) -> String {
    let new_key = crate::keyfile::derive_keyfile_content(&request.new_password);
    let old_key = crate::keyfile::derive_keyfile_content(&request.current_password);
    if overlap && old_key != new_key {
        serde_json::to_string(&[old_key, new_key]).unwrap()
    } else {
        new_key
    }
}
fn healthy_set(status: &crate::mongo::RsStatus) -> bool {
    matches!(status, crate::mongo::RsStatus::Active { members, .. } if members.len() >= 3 && members.iter().filter(|m| m.state == 1).count() == 1 && members.iter().all(|m| m.healthy && matches!(m.state, 1 | 2)) && crate::mongo::has_majority(members))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rotation {
    operation: Operation,
    new_password: String,
    current_password: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Preflight,
    Prepare,
    Database,
    Member,
    Verify,
    KeyStatus,
    KeyPrepare,
    KeyCommit,
}

pub async fn rotate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<Rotation>,
) -> (StatusCode, Json<Value>) {
    let _guard = ROTATION.lock().await;
    let active = read_pin(&state.config.data_dir)
        .map(|p| p.password)
        .unwrap_or_else(|| state.config.mongo_root_password.clone());
    let expected = format!("railway:{active}");
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .and_then(|(_, token)| base64::engine::general_purpose::STANDARD.decode(token).ok());
    if !supplied.is_some_and(|s| bool::from(s.as_slice().ct_eq(expected.as_bytes()))) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"unauthorized"})),
        );
    }
    if request.new_password.is_empty() || request.new_password.len() > 1024 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid password"})),
        );
    }
    // Errors are intentionally opaque: driver errors can include commands,
    // credentials and URLs. The platform identifies the phase and member.
    match tokio::time::timeout(std::time::Duration::from_secs(35), apply(&state, request)).await {
        Ok(Ok(value)) => (StatusCode::OK, Json(value)),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"credential rotation could not be verified"})),
        ),
    }
}

async fn apply(state: &AppState, request: Rotation) -> anyhow::Result<Value> {
    match request.operation {
        Operation::Preflight => {
            anyhow::ensure!(
                loaded_keyfile().as_deref() == Some(&target_keyfile(&request, false)),
                "keyfile and root password are not coupled"
            );
            anyhow::ensure!(
                matches!(
                    state
                        .mongo
                        .probe_local_password(&request.new_password)
                        .await,
                    PasswordProbe::Works
                ),
                "current password refused"
            );
            state.mongo.ping().await?;
            let status = state.mongo.rs_status().await?;
            anyhow::ensure!(healthy_set(&status), "cluster not healthy");
        }
        Operation::Prepare => {
            save_pending(&state.config.data_dir, &request)?;
            return Ok(json!({"version": 1, "leader": false}));
        }
        Operation::Database => {
            if !matches!(
                state
                    .mongo
                    .probe_local_password(&request.new_password)
                    .await,
                PasswordProbe::Works
            ) {
                anyhow::ensure!(
                    matches!(
                        state
                            .mongo
                            .probe_local_password(&request.current_password)
                            .await,
                        PasswordProbe::Works
                    ),
                    "current password refused"
                );
                state.mongo.swap_password(&request.current_password).await;
                anyhow::ensure!(
                    state.mongo.hello().await?.is_writable_primary,
                    "not primary"
                );
                state
                    .mongo
                    .run_admin(doc! {
                        "updateUser": &state.config.mongo_root_username,
                        "pwd": &request.new_password,
                        "writeConcern": {"w": "majority", "wtimeout": 30000},
                    })
                    .await?;
            }
            state.mongo.swap_password(&request.new_password).await;
        }
        Operation::Member => {
            anyhow::ensure!(
                matches!(
                    state
                        .mongo
                        .probe_local_password(&request.new_password)
                        .await,
                    PasswordProbe::Works
                ),
                "new password not replicated"
            );
            state.mongo.swap_password(&request.new_password).await;
            crate::auth_pin::write_password_pin(
                &state.config.data_dir,
                &request.new_password,
                loaded_keyfile(),
            )?;
        }
        Operation::KeyStatus => {
            anyhow::ensure!(
                healthy_set(&state.mongo.rs_status().await?),
                "replica set not healthy"
            );
        }
        Operation::KeyPrepare | Operation::KeyCommit => {
            anyhow::ensure!(
                matches!(
                    state
                        .mongo
                        .probe_local_password(&request.new_password)
                        .await,
                    PasswordProbe::Works
                ),
                "target root password refused"
            );
            let target =
                target_keyfile(&request, matches!(request.operation, Operation::KeyPrepare));
            if loaded_keyfile().as_ref() != Some(&target) {
                anyhow::ensure!(
                    healthy_set(&state.mongo.rs_status().await?),
                    "replica set not healthy before restart"
                );
                // The pin is durable restart intent. On process/container loss,
                // startup renders this exact keyfile before starting mongod.
                write_pin(
                    &state.config.data_dir,
                    &AuthPin {
                        password: request.new_password.clone(),
                        keyfile: Some(target.clone()),
                    },
                )?;
                RESTART_MONGO.notify_one();
            }
            loop {
                if loaded_keyfile().as_ref() == Some(&target)
                    && state
                        .mongo
                        .rs_status()
                        .await
                        .is_ok_and(|status| healthy_set(&status))
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        }
        Operation::Verify => {
            anyhow::ensure!(
                loaded_keyfile().as_deref() == Some(&target_keyfile(&request, false)),
                "previous internal key still loaded"
            );
            anyhow::ensure!(
                read_pin(&state.config.data_dir)
                    .and_then(|p| p.keyfile)
                    .as_deref()
                    == Some(&target_keyfile(&request, false)),
                "keyfile pin differs"
            );
            let status = state.mongo.rs_status().await?;
            anyhow::ensure!(healthy_set(&status), "cluster not healthy");
            if request.current_password != request.new_password {
                anyhow::ensure!(
                    matches!(
                        state
                            .mongo
                            .probe_local_password(&request.current_password)
                            .await,
                        PasswordProbe::AccessDenied
                    ),
                    "previous password still accepted"
                );
            }
            anyhow::ensure!(
                matches!(
                    state
                        .mongo
                        .probe_local_password(&request.new_password)
                        .await,
                    PasswordProbe::Works
                ),
                "new password refused"
            );
            anyhow::ensure!(
                read_pin(&state.config.data_dir)
                    .is_some_and(|p| p.password == request.new_password),
                "pin differs"
            );
            state.mongo.ping().await?;
            match std::fs::remove_file(format!("{}/.railway_rotation", state.config.data_dir)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(json!({"version": 1, "leader": state.mongo.hello().await?.is_writable_primary}))
}

fn save_pending(data_dir: &str, request: &Rotation) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = format!("{data_dir}/.railway_rotation");
    let tmp = format!("{path}.tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&serde_json::to_vec(request)?)?;
    file.sync_all()?;
    std::fs::rename(tmp, path)?;
    std::fs::File::open(data_dir)?.sync_all()?;
    Ok(())
}
pub fn pending_password(data_dir: &str) -> Option<String> {
    let request: Rotation =
        serde_json::from_slice(&std::fs::read(format!("{data_dir}/.railway_rotation")).ok()?)
            .ok()?;
    Some(request.new_password)
}
pub async fn reconcile(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _lock = ROTATION.lock().await;
        let attempt = async {
            let path = format!("{}/.railway_rotation", state.config.data_dir);
            anyhow::ensure!(
                std::fs::metadata(&path)?.modified()?.elapsed()?.as_secs() >= 30,
                "normal ordered phase"
            );
            let mut request: Rotation = serde_json::from_slice(&std::fs::read(path)?)?;
            request.operation = Operation::Member;
            apply(&state, request).await?;
            Ok::<(), anyhow::Error>(())
        };
        let _ = tokio::time::timeout(std::time::Duration::from_secs(25), attempt).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn two_pass_keys_overlap_then_revoke_the_original() {
        let request = Rotation {
            operation: Operation::KeyPrepare,
            new_password: "target".into(),
            current_password: "previous".into(),
        };
        let keys: Vec<String> = serde_json::from_str(&target_keyfile(&request, true)).unwrap();
        assert_eq!(
            keys,
            vec![
                crate::keyfile::derive_keyfile_content("previous"),
                crate::keyfile::derive_keyfile_content("target")
            ]
        );
        assert_eq!(target_keyfile(&request, false), keys[1]);
        let reverse = Rotation {
            operation: Operation::KeyPrepare,
            new_password: "previous".into(),
            current_password: "target".into(),
        };
        let rollback: Vec<String> = serde_json::from_str(&target_keyfile(&reverse, true)).unwrap();
        assert!(rollback.iter().all(|key| keys.contains(key)));
        assert_eq!(target_keyfile(&reverse, false), keys[0]);
        assert!(keys_overlap(&target_keyfile(&request, true), &keys[0]));
        assert!(keys_overlap(&target_keyfile(&request, true), &keys[1]));
        assert!(!keys_overlap(&keys[0], &keys[1]));
    }
}

fn keys_overlap(left: &str, right: &str) -> bool {
    let keys = |text: &str| {
        serde_json::from_str::<Vec<String>>(text).unwrap_or_else(|_| vec![text.trim().into()])
    };
    let left = keys(left);
    keys(right).iter().any(|key| left.contains(key))
}
/// A node which missed the final pass must not start with a disjoint key.
/// Prove a root credential against a live peer before accepting its keyfile;
/// retain compatible local restart intent during an unfinished rolling pass.
pub async fn reconcile_keyfile_at_boot(config: &crate::config::Config) -> anyhow::Result<()> {
    let Some(mut pin) = read_pin(&config.data_dir) else {
        return Ok(());
    };
    let Some(current) = pin.keyfile.as_deref() else {
        return Ok(());
    };
    let pending = std::fs::read(format!("{}/.railway_rotation", config.data_dir))
        .ok()
        .and_then(|raw| serde_json::from_slice::<Rotation>(&raw).ok());
    if pending.is_none() && pin.password == config.mongo_root_password {
        return Ok(());
    }
    let mut candidates = vec![config.mongo_root_password.clone(), pin.password.clone()];
    if let Some(request) = pending {
        candidates.insert(0, request.current_password);
        candidates.insert(0, request.new_password);
    }
    let probe = async {
        for password in candidates {
            if let Some(keyfile) =
                crate::rs::discover_live_set_keyfile_with_password(config, &password).await
            {
                return Some(keyfile);
            }
        }
        None
    };
    if let Ok(Some(keyfile)) = tokio::time::timeout(std::time::Duration::from_secs(20), probe).await
    {
        if !keys_overlap(current, &keyfile) {
            pin.keyfile = Some(keyfile);
            write_pin(&config.data_dir, &pin)?;
        }
    }
    Ok(())
}
