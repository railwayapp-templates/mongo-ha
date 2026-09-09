//! Peer state exchange over the health servers.
//!
//! Each node serves GET /rs/state (see health_server.rs); the orchestrator
//! queries its declared peers with it before making any initiate/join
//! decision. This is the replica set analogue of redis-ha's peer-Sentinel
//! boot query and mysql-ha's /gr/state: never trust only local state when
//! deciding whether a live set exists.

use crate::mongo::PASSWORD_PROBE_TIMEOUT;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::debug;

/// Margin a joiner adds on top of the peer's credential-probe budget when it
/// asks for the keyfile. The peer answers `/rs/keyfile` only after probing the
/// password against its own mongod — up to `PASSWORD_PROBE_TIMEOUT` when that
/// mongod is slow — and the answer still has to cross the network. A fetch
/// that gives up earlier reads a slow peer as "no answer": the joiner then
/// derives its keyfile from RS_KEY while the peer was about to hand out the
/// live one, and joins with a keyfile the set may refuse.
pub const KEYFILE_FETCH_MARGIN: Duration = Duration::from_secs(2);

/// The per-peer timeout of a keyfile fetch: the configured peer query
/// timeout, raised to the probe budget plus the margin when it is shorter
/// (the default 2s `/rs/state` timeout is).
pub fn keyfile_fetch_timeout(peer_query_timeout: Duration) -> Duration {
    peer_query_timeout.max(PASSWORD_PROBE_TIMEOUT + KEYFILE_FETCH_MARGIN)
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    #[test]
    fn a_keyfile_fetch_outlasts_the_peers_probe_budget() {
        // PEER_QUERY_TIMEOUT_MS defaults to 2000 (config.rs), shorter than the
        // peer's probe budget; the keyfile fetch must not be.
        let default_peer_query = Duration::from_millis(2000);
        assert!(default_peer_query < PASSWORD_PROBE_TIMEOUT);
        assert!(
            keyfile_fetch_timeout(default_peer_query)
                >= PASSWORD_PROBE_TIMEOUT + KEYFILE_FETCH_MARGIN
        );
        // A longer configured timeout is kept as it is.
        let long = Duration::from_secs(30);
        assert_eq!(keyfile_fetch_timeout(long), long);
    }
}

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

/// Ask a peer for the keyfile its set runs with, proving the root password
/// (the peer verifies it against its own mongod before answering — see
/// health_server::rs_keyfile). None on any refusal or transport failure.
pub async fn fetch_keyfile(
    client: &reqwest::Client,
    host: &str,
    health_port: u16,
    timeout: Duration,
    username: &str,
    password: &str,
) -> Option<String> {
    let url = format!("http://{host}:{health_port}/rs/keyfile");
    match client
        .post(&url)
        .timeout(keyfile_fetch_timeout(timeout))
        .json(&KeyfileRequest { username, password })
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => resp
            .text()
            .await
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        Ok(resp) => {
            debug!(host, status = %resp.status(), "peer /rs/keyfile refused");
            None
        }
        Err(e) => {
            debug!(host, error = %format!("{e:#}"), "peer /rs/keyfile unreachable");
            None
        }
    }
}
