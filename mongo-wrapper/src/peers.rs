//! Peer state exchange over the health servers.
//!
//! Each node serves GET /rs/state (see health_server.rs); the orchestrator
//! queries its declared peers with it before making any initiate/join
//! decision. This is the replica set analogue of redis-ha's peer-Sentinel
//! boot query and mysql-ha's /gr/state: never trust only local state when
//! deciding whether a live set exists.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::debug;

/// A node's self-reported replica set state. Also the /rs/state body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsState {
    /// This node as the set names it (`host:port`).
    pub node_id: String,
    /// True when this node holds a replica set config — i.e. "a set exists,
    /// join it, do not initiate". A member of a set with no primary right now
    /// (mid-election, total-outage recovery) still counts: mongod re-forms
    /// that set natively from the persisted config.
    pub set_active: bool,
    pub set_name: Option<String>,
    /// mongod's `stateStr` for this node (PRIMARY, SECONDARY, STARTUP2, ...).
    pub my_state: Option<String>,
    pub is_primary: bool,
    /// `host:port` of the primary this node currently sees, if any.
    pub primary_host: Option<String>,
    /// Every `host:port` in this node's replica set config.
    #[serde(default)]
    pub members: Vec<String>,
    pub members_total: usize,
    pub members_healthy: usize,
    /// Members whose vote counts right now (`votingMembersCount`). A member
    /// that just joined is non-voting (`newlyAdded`) until its initial sync
    /// completes and the primary's automatic reconfig commits, so a set can
    /// read fully healthy and still be one node away from being unable to
    /// elect. Absent on servers that do not report the field.
    #[serde(default)]
    pub voting_members: Option<usize>,
    /// True when this node's data dir already held an initialized mongod
    /// dataset when the container started — an adopted standalone volume (or
    /// a returning member), never a fresh node the entrypoint just
    /// initialized. Decided before mongod spawns, from the same files the
    /// upstream entrypoint checks. It outranks fresh nodes in the initiate
    /// tie-break: a fresh node initiating an empty set over it would make the
    /// adopted data a joiner's initial-sync casualty.
    pub has_data: bool,
    pub config_version: Option<i64>,
}

/// One peer's answer, or why there isn't one. The distinction matters: an
/// unreachable peer blocks initiation (it may hold the set, or the data),
/// while a reachable peer with no set is a vote in favor.
#[derive(Debug)]
pub enum PeerAnswer {
    State(RsState),
    /// The health server answered but mongod behind it isn't ready (503) —
    /// treated the same as unreachable: nothing to compare yet.
    NotReady,
    Unreachable,
}

pub async fn query_peer(
    client: &reqwest::Client,
    host: &str,
    health_port: u16,
    timeout: Duration,
) -> PeerAnswer {
    let url = format!("http://{host}:{health_port}/rs/state");
    match client.get(&url).timeout(timeout).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<RsState>().await {
            Ok(state) => PeerAnswer::State(state),
            Err(e) => {
                debug!(host, error = %format!("{e:#}"), "peer /rs/state returned unparseable body");
                PeerAnswer::NotReady
            }
        },
        Ok(resp) => {
            debug!(host, status = %resp.status(), "peer /rs/state not ready");
            PeerAnswer::NotReady
        }
        Err(e) => {
            debug!(host, error = %format!("{e:#}"), "peer /rs/state unreachable");
            PeerAnswer::Unreachable
        }
    }
}

#[derive(Serialize)]
struct KeyfileRequest<'a> {
    username: &'a str,
    password: &'a str,
}

/// What a peer's `/rs/keyfile` said. Only `Refused` is a credential verdict:
/// the peer's own mongod judged the root password wrong. Everything else is
/// "cannot tell" or "cannot help", never evidence about the password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyfileFetch {
    /// The set's keyfile, handed out against the root password.
    Keyfile(String),
    /// 401: the peer's mongod refused the root password.
    Refused,
    /// 503 or a transport failure: the peer cannot judge right now.
    Unavailable,
    /// Any other answer — a 404 from an image without the route, an empty
    /// body: this peer cannot hand a keyfile out at all.
    Unsupported,
}

/// Map an HTTP reply from `/rs/keyfile` to a fetch outcome.
pub fn classify_keyfile_reply(status: u16, body: Option<&str>) -> KeyfileFetch {
    match status {
        200..=299 => match body.map(str::trim).filter(|s| !s.is_empty()) {
            Some(keyfile) => KeyfileFetch::Keyfile(keyfile.to_string()),
            None => KeyfileFetch::Unsupported,
        },
        401 => KeyfileFetch::Refused,
        503 => KeyfileFetch::Unavailable,
        _ => KeyfileFetch::Unsupported,
    }
}

/// Ask a peer for the keyfile its set runs with, proving the root password
/// (the peer verifies it against its own mongod before answering — see
/// health_server::rs_keyfile).
pub async fn fetch_keyfile(
    client: &reqwest::Client,
    host: &str,
    health_port: u16,
    timeout: Duration,
    username: &str,
    password: &str,
) -> KeyfileFetch {
    let url = format!("http://{host}:{health_port}/rs/keyfile");
    match client
        .post(&url)
        .timeout(timeout)
        .json(&KeyfileRequest { username, password })
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.ok();
            let fetch = classify_keyfile_reply(status.as_u16(), body.as_deref());
            if !matches!(fetch, KeyfileFetch::Keyfile(_)) {
                debug!(host, %status, ?fetch, "peer /rs/keyfile did not hand out the keyfile");
            }
            fetch
        }
        Err(e) => {
            debug!(host, error = %format!("{e:#}"), "peer /rs/keyfile unreachable");
            KeyfileFetch::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyfile_replies_classify_by_status_and_body() {
        assert_eq!(
            classify_keyfile_reply(200, Some(" KEY== \n")),
            KeyfileFetch::Keyfile("KEY==".into())
        );
        assert_eq!(
            classify_keyfile_reply(200, Some("  ")),
            KeyfileFetch::Unsupported
        );
        assert_eq!(classify_keyfile_reply(200, None), KeyfileFetch::Unsupported);
        assert_eq!(
            classify_keyfile_reply(401, Some("authentication failed")),
            KeyfileFetch::Refused
        );
        assert_eq!(
            classify_keyfile_reply(503, Some("mongod not ready")),
            KeyfileFetch::Unavailable
        );
        // A standalone node or an image without the route: not a verdict.
        assert_eq!(classify_keyfile_reply(404, None), KeyfileFetch::Unsupported);
        assert_eq!(classify_keyfile_reply(405, None), KeyfileFetch::Unsupported);
    }
}
