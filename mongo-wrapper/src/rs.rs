//! Replica set orchestration: decide initiate-vs-join, guarded; then the
//! duties of a member (role telemetry, membership pruning).
//!
//! Runs as a background task next to the mongod supervisor. mongod persists
//! the replica set config in its `local` database and re-forms the set by
//! itself on every restart — elections, catch-up, initial sync and total-
//! outage recovery are the server's own. What mongod does NOT do is decide
//! how a node with no config yet becomes a member: whether to `replSetInitiate`
//! a brand-new set or to be added to an existing one. That decision is this
//! module's whole job, and it is the one place a wrong choice destroys data:
//! a fresh node initiating an empty set beside an adopted standalone volume
//! turns that volume into a joiner, and a joiner's data is replaced by
//! initial sync.
//!
//! Invariants:
//!   - NEVER initiate while any declared peer is unreachable or not yet
//!     answering: an unreachable peer may hold the set, or the data. (First
//!     deploys don't trip this: health servers come up well before mongod
//!     finishes initializing, so peers answer "no set, no data" almost
//!     immediately.) ONE exception, with proof: a peer whose NAME is
//!     authoritatively gone (continuous NXDOMAIN for the whole
//!     `peer_gone_dwell_seconds`) stops being waited on — RS_SEEDS is stamped
//!     at deploy time and scale-down never restamps the survivors, so a
//!     deleted member would otherwise freeze every future fresh boot forever.
//!     The private resolver answers NXDOMAIN only when zero live containers
//!     are registered behind the name; a partition yields SERVFAIL, never
//!     NXDOMAIN (see dns_probe.rs).
//!   - Joining is the default: any peer holding a set means this node joins
//!     it. A node that is already named in that set's config only has to
//!     wait — the primary delivers the config over heartbeats and initial
//!     sync starts on its own (a wiped volume rejoining under its old name).
//!     Otherwise the node adds ITSELF through the primary with a safe
//!     reconfig, so scale-up needs no restamping of the survivors' RS_SEEDS.
//!   - When no set exists anywhere, the node holding user data initiates
//!     (an adopted standalone volume must beat the fresh nodes its data
//!     hasn't reached); identical standings tie-break on declared seed
//!     order. Every node computes the same order, so exactly one wins.
//!   - The initiate decision must hold stable for a dwell period before it
//!     is acted on, so a slow-starting peer gets a window to contradict it.
//!   - A member the set can no longer reach is removed from the config only
//!     on the same NXDOMAIN proof, by the primary — so a scale-down shrinks
//!     the majority requirement instead of leaving ghosts that vote against
//!     every future election.

use crate::config::Config;
use crate::dns_probe::{probe_name_detailed, NameVerdict};
use crate::mongo::{
    codes, command_error_code, config_member_hosts, config_with_member_added,
    config_with_member_removed, split_host_port, states, Hello, Mongo, RsStatus,
};
use crate::peers::{fetch_keyfile, query_peer, PeerAnswer, RsState};
use anyhow::{Context, Result};
use common::{Telemetry, TelemetryEvent};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

const POLL_INTERVAL: Duration = Duration::from_secs(3);
/// mongod's state code for a member that was removed from the set's config.
const STATE_REMOVED: i32 = 10;

/// Wait for the FINAL mongod. The upstream entrypoint's first-boot
/// initialization runs against a temporary server it starts WITHOUT
/// `--replSet`/`--keyFile`/`--auth` — the root user is created there, so our
/// authenticated `hello` starts succeeding against it — and touching that
/// server would race the init. In HA mode the final server is the one that
/// reports replication enabled. No timeout: the supervisor exits the
/// container if mongod dies.
pub async fn wait_for_final_mongod(mongo: &Mongo, config: &Config) -> Hello {
    let mut attempts = 0u32;
    loop {
        match mongo.hello().await {
            Ok(h) if config.rs_enabled() && !h.replication_enabled() => {
                if attempts.is_multiple_of(30) {
                    info!("waiting out docker-entrypoint's init temp server");
                }
            }
            Ok(h) => return h,
            Err(e) => {
                if attempts.is_multiple_of(30) {
                    info!(attempts, error = %e, "still waiting for mongod");
                }
            }
        }
        attempts += 1;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// This node's own /rs/state answer, computed live.
///
/// `has_data` is decided BEFORE mongod spawns (see main.rs): whether the data
/// dir already held an initialized mongod dataset when this container
/// started. It cannot be read from the running server: a `--replSet` member
/// with no config yet refuses every read command ("node is not in primary or
/// recovering state"), so a `listDatabases`-based answer would keep
/// `/rs/state` at 503 on every fresh node and freeze the whole initiate
/// decision — every peer "not ready", nobody ever initiating.
pub async fn local_rs_state(mongo: &Mongo, config: &Config, has_data: bool) -> Result<RsState> {
    let status = mongo.rs_status().await?;
    let node_id = config.node_id();
    Ok(match status {
        RsStatus::NotInitialized => RsState {
            node_id,
            set_active: false,
            set_name: None,
            my_state: None,
            is_primary: false,
            primary_host: None,
            members: vec![],
            members_total: 0,
            members_healthy: 0,
            has_data,
            config_version: None,
        },
        RsStatus::Active {
            set_name,
            my_state,
            my_state_str,
            members,
        } => {
            let primary_host = members
                .iter()
                .find(|m| m.state == states::PRIMARY)
                .map(|m| m.host.clone());
            let config_version = mongo.rs_config().await.ok().and_then(|c| {
                c.get_i64("version")
                    .ok()
                    .or(c.get_i32("version").ok().map(i64::from))
            });
            RsState {
                node_id,
                // A member REMOVED from the config still answers replSetGetStatus
                // (with state 10); it is not part of any set anymore.
                set_active: my_state != STATE_REMOVED,
                set_name: Some(set_name),
                my_state: Some(my_state_str),
                is_primary: my_state == states::PRIMARY,
                primary_host,
                members_total: members.len(),
                members_healthy: members.iter().filter(|m| m.healthy || m.is_self).count(),
                members: members.into_iter().map(|m| m.host).collect(),
                has_data,
                config_version,
            }
        }
    })
}

/// How long each unreachable peer's NAME has been authoritatively gone (see
/// the module doc). Any non-Gone observation resets its clock, so the proof
/// must hold uninterrupted.
pub struct GoneTracker {
    gone_since: HashMap<String, Instant>,
}

impl GoneTracker {
    pub fn new() -> Self {
        Self {
            gone_since: HashMap::new(),
        }
    }

    pub fn observe(&mut self, host: &str, verdict: NameVerdict, now: Instant) {
        match verdict {
            NameVerdict::Gone => {
                self.gone_since.entry(host.to_string()).or_insert(now);
            }
            NameVerdict::ExistsOrUnknown => {
                self.gone_since.remove(host);
            }
        }
    }

    /// A reachable peer is present again by definition — its clock resets.
    pub fn observe_reachable(&mut self, host: &str) {
        self.gone_since.remove(host);
    }

    pub fn is_waived(&self, host: &str, now: Instant, dwell: Duration) -> bool {
        self.gone_since
            .get(host)
            .is_some_and(|since| now.duration_since(*since) >= dwell)
    }
}

/// One peer's standing in an initiate round.
#[derive(Debug, Clone, PartialEq)]
pub enum PeerStanding {
    /// Holds a replica set config — the set exists; join it.
    InSet { primary_host: Option<String> },
    /// Answered, no set; whether it holds user data decides the tie-break.
    NoSet { has_data: bool },
    /// Unreachable or not ready — no safe decision exists.
    Unknown,
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// Some peer is in a set — join it (through its primary, once known).
    JoinExisting { primary_host: Option<String> },
    /// Every peer answered, none has a set, and we win every tie.
    SafeToInitiate,
    /// A peer with no set outranks us (holds data we don't, or precedes us in
    /// seed order): it initiates, we join its set.
    DeferTo(String),
    /// At least one peer is unreachable/not ready.
    Undecidable,
}

fn standing_of(answer: &PeerAnswer) -> PeerStanding {
    match answer {
        PeerAnswer::State(RsState {
            set_active: true,
            primary_host,
            ..
        }) => PeerStanding::InSet {
            primary_host: primary_host.clone(),
        },
        PeerAnswer::State(RsState { has_data, .. }) => PeerStanding::NoSet {
            has_data: *has_data,
        },
        PeerAnswer::NotReady | PeerAnswer::Unreachable => PeerStanding::Unknown,
    }
}

/// The pure initiate decision. Blocking verdicts are checked in order of how
/// definitive they are: a live set anywhere means join; an unanswered peer
/// voids the round; then the tie-break — user data first (an adopted volume
/// must beat the fresh nodes its data hasn't reached), declared seed order
/// second. A peer not in our declared seeds (scaled in after our RS_SEEDS was
/// stamped) ranks last, as does a node that cannot find itself.
pub fn decide(
    my_has_data: bool,
    my_seed_rank: Option<usize>,
    peers: &[(String, Option<usize>, PeerStanding)],
) -> Verdict {
    if let Some((_, _, PeerStanding::InSet { primary_host })) = peers
        .iter()
        .find(|(_, _, s)| matches!(s, PeerStanding::InSet { .. }))
    {
        // Prefer a peer that actually knows who the primary is.
        let primary_host = peers
            .iter()
            .find_map(|(_, _, s)| match s {
                PeerStanding::InSet {
                    primary_host: Some(p),
                } => Some(p.clone()),
                _ => None,
            })
            .or_else(|| primary_host.clone());
        return Verdict::JoinExisting { primary_host };
    }
    if peers.iter().any(|(_, _, s)| *s == PeerStanding::Unknown) {
        return Verdict::Undecidable;
    }
    let my_rank = my_seed_rank.unwrap_or(usize::MAX);
    for (host, rank, standing) in peers {
        if let PeerStanding::NoSet { has_data } = standing {
            let peer_wins = match (has_data, my_has_data) {
                (true, false) => true,
                (false, true) => false,
                _ => rank.unwrap_or(usize::MAX) < my_rank,
            };
            if peer_wins {
                return Verdict::DeferTo(host.clone());
            }
        }
    }
    Verdict::SafeToInitiate
}

/// Query every declared peer concurrently.
async fn query_peers(
    client: &reqwest::Client,
    config: &Config,
    hosts: &[String],
) -> Vec<(String, PeerAnswer)> {
    let timeout = Duration::from_millis(config.peer_query_timeout_ms);
    let handles: Vec<_> = hosts
        .iter()
        .cloned()
        .map(|host| {
            let client = client.clone();
            let port = config.health_port;
            tokio::spawn(async move {
                let answer = query_peer(&client, &host, port, timeout).await;
                (host, answer)
            })
        })
        .collect();
    let mut answers = Vec::with_capacity(handles.len());
    for h in handles {
        match h.await {
            Ok(a) => answers.push(a),
            Err(e) => warn!(error = %e, "peer query task failed"),
        }
    }
    answers
}

/// One round over the declared peers, BEFORE mongod spawns on a node with no
/// credential pin: if any peer already holds a set, this node must run with
/// THAT set's keyfile — its own derivation from RS_KEY may no longer match
/// (the variable drifted since the set formed). The peer hands the keyfile
/// out only against the root password it can verify locally. None when no
/// peer holds a set, none answers, or none accepts the credentials — the
/// caller then derives from the environment, exactly the pre-pin behavior.
pub async fn discover_live_set_keyfile(config: &Config) -> Option<String> {
    let http = reqwest::Client::new();
    let peer_hosts = config.peer_hosts();
    if peer_hosts.is_empty() {
        return None;
    }
    let timeout = Duration::from_millis(config.peer_query_timeout_ms);
    let answers = query_peers(&http, config, &peer_hosts).await;
    for (host, answer) in &answers {
        if !matches!(
            answer,
            PeerAnswer::State(RsState {
                set_active: true,
                ..
            })
        ) {
            continue;
        }
        if let Some(keyfile) = fetch_keyfile(
            &http,
            host,
            config.health_port,
            timeout,
            &config.mongo_root_username,
            &config.mongo_root_password,
        )
        .await
        {
            info!(%host, "adopted the live set's keyfile from a peer");
            return Some(keyfile);
        }
        warn!(%host, "peer holds a set but did not hand out its keyfile; falling back to RS_KEY");
    }
    None
}

/// Add this node to the live set through its primary. `Ok(true)` when a
/// reconfig was issued, `Ok(false)` when the config already names us (the
/// primary will deliver it over heartbeats).
async fn add_self_through_primary(
    config: &Config,
    primary_host: &str,
    my_has_data: bool,
    telemetry: &Telemetry,
) -> Result<bool> {
    let primary = Mongo::connect_member(
        primary_host,
        &config.mongo_root_username,
        &config.mongo_root_password,
    );
    let current = primary
        .rs_config()
        .await
        .with_context(|| format!("reading the set's config from {primary_host}"))?;
    let me = config.node_id();
    if config_member_hosts(&current)
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&me))
    {
        info!(
            %primary_host,
            "already named in the set's config; waiting for the primary to deliver it"
        );
        return Ok(false);
    }
    if my_has_data {
        // The set formed without this node's data. Joining is still the
        // right call — the live set is the platform's source of truth — but
        // initial sync will replace what this volume holds, so say so where
        // an operator will see it.
        let error = format!(
            "this node holds user data but is not part of the live set at {primary_host}; \
             joining it — initial sync will replace the local data"
        );
        error!("{error}");
        telemetry.send(TelemetryEvent::ComponentError {
            component: "mongo-wrapper".to_string(),
            error,
            context: "join".to_string(),
        });
    }
    let next = config_with_member_added(&current, &me)?;
    primary
        .rs_reconfig(next)
        .await
        .with_context(|| format!("adding {me} to the set through {primary_host}"))?;
    info!(%primary_host, node = %me, "added to the replica set");
    Ok(true)
}

/// The main orchestration loop. Returns once this node is a member (any state
/// but REMOVED); `member_duties` takes over from there.
pub async fn orchestrate(
    config: Arc<Config>,
    mongo: Mongo,
    telemetry: Arc<Telemetry>,
    my_has_data: bool,
) {
    let hello = wait_for_final_mongod(&mongo, &config).await;
    info!(
        set_name = ?hello.set_name,
        initiated = hello.set_name.is_some(),
        "mongod is answering"
    );

    let http = reqwest::Client::new();
    let peer_hosts = config.peer_hosts();
    let dwell = Duration::from_secs(config.bootstrap_dwell_seconds);
    let gone_dwell = Duration::from_secs(config.peer_gone_dwell_seconds);
    let mut gone = GoneTracker::new();
    let mut stable_since: Option<Instant> = None;
    let mut last_log = String::new();

    loop {
        let status = match mongo.rs_status().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "replSetGetStatus failed; retrying");
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
        };
        let removed =
            matches!(status, RsStatus::Active { my_state, .. } if my_state == STATE_REMOVED);
        if let RsStatus::Active { my_state_str, .. } = &status {
            if !removed {
                info!(state = %my_state_str, "member of the replica set");
                break;
            }
            if wait_log_once(&mut last_log, "removed") {
                warn!("this node was removed from the set's config; seeking to be re-added");
            }
        }

        let answers = query_peers(&http, &config, &peer_hosts).await;
        let now = Instant::now();
        let mut peers = Vec::with_capacity(answers.len());
        for (host, answer) in &answers {
            let standing = standing_of(answer);
            if standing == PeerStanding::Unknown {
                let (verdict, detail) = probe_name_detailed(host, Duration::from_secs(2)).await;
                gone.observe(host, verdict, now);
                if gone.is_waived(host, now, gone_dwell) {
                    warn!(%host, "peer name authoritatively gone for the whole dwell; waived from this round");
                    continue;
                }
                debug!(%host, ?verdict, ?detail, "peer unavailable");
            } else {
                gone.observe_reachable(host);
            }
            peers.push((host.clone(), config.seed_rank(host), standing));
        }

        // A REMOVED member's own local view still says "in a set" — but it
        // is not; only its peers' view counts for it.
        let verdict = decide(my_has_data, config.my_seed_rank(), &peers);
        match verdict {
            Verdict::JoinExisting { primary_host } => {
                stable_since = None;
                match primary_host {
                    Some(primary) => {
                        match add_self_through_primary(&config, &primary, my_has_data, &telemetry)
                            .await
                        {
                            Ok(_) => last_log.clear(),
                            Err(e) => {
                                let code = command_error_code(&e);
                                if matches!(
                                    code,
                                    Some(codes::CONFIGURATION_IN_PROGRESS)
                                        | Some(codes::NEW_CONFIG_INCOMPATIBLE)
                                        | Some(codes::NOT_WRITABLE_PRIMARY)
                                ) {
                                    if wait_log_once(&mut last_log, "reconfig-retry") {
                                        info!(error = %e, "set busy or primary moved; retrying the join");
                                    }
                                } else if wait_log_once(&mut last_log, "join-error") {
                                    warn!(error = %e, "join attempt failed; retrying");
                                }
                            }
                        }
                    }
                    None => {
                        if wait_log_once(&mut last_log, "no-primary") {
                            info!("a set exists but no peer sees a primary yet; waiting");
                        }
                    }
                }
            }
            Verdict::SafeToInitiate => {
                if removed {
                    // Nobody holds a set anymore and we were removed from the
                    // last one: our old config would only confuse things.
                    // Fall through to initiate — mongod refuses initiate on
                    // a node with a config, so log and wait for peers.
                    if wait_log_once(&mut last_log, "removed-no-set") {
                        warn!("removed from a set that no peer holds anymore; waiting for a set to appear");
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
                let since = *stable_since.get_or_insert(now);
                let held = now.duration_since(since);
                if held < dwell {
                    if wait_log_once(&mut last_log, "dwell") {
                        info!(
                            dwell_secs = dwell.as_secs(),
                            "safe to initiate; holding the decision through the dwell"
                        );
                    }
                } else {
                    let me = config.node_id();
                    info!(set_name = %config.rs_name, node = %me, peers = ?peer_hosts, "initiating a new replica set");
                    match mongo.rs_initiate(&config.rs_name, &me).await {
                        Ok(()) => {
                            telemetry.send(TelemetryEvent::NodeStarted {
                                node: config.private_domain.clone(),
                                role: "primary".to_string(),
                            });
                        }
                        Err(e) if command_error_code(&e) == Some(codes::ALREADY_INITIALIZED) => {
                            info!("set already initiated on this node");
                        }
                        Err(e) => {
                            error!(error = %e, "replSetInitiate failed; retrying");
                            telemetry.send(TelemetryEvent::ComponentError {
                                component: "mongo-wrapper".to_string(),
                                error: e.to_string(),
                                context: "replSetInitiate".to_string(),
                            });
                        }
                    }
                    stable_since = None;
                }
            }
            Verdict::DeferTo(host) => {
                stable_since = None;
                if wait_log_once(&mut last_log, &format!("defer-{host}")) {
                    info!(%host, "peer outranks this node for initiation; waiting for its set");
                }
            }
            Verdict::Undecidable => {
                stable_since = None;
                if wait_log_once(&mut last_log, "undecidable") {
                    let missing: Vec<&String> = peers
                        .iter()
                        .filter(|(_, _, s)| *s == PeerStanding::Unknown)
                        .map(|(h, _, _)| h)
                        .collect();
                    info!(
                        ?missing,
                        "peers not answering yet; no initiate decision until they do"
                    );
                }
            }
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }

    member_duties(config, mongo, telemetry).await;
}

/// Runs for the rest of the process: role-change telemetry, and — while this
/// node is the primary — removal of members whose names are provably gone.
async fn member_duties(config: Arc<Config>, mongo: Mongo, telemetry: Arc<Telemetry>) {
    let mut last_role: Option<String> = None;
    let mut gone = GoneTracker::new();
    let gone_dwell = Duration::from_secs(config.peer_gone_dwell_seconds);
    loop {
        match mongo.hello().await {
            Ok(h) => {
                let role = if h.is_writable_primary {
                    "primary"
                } else if h.secondary {
                    "secondary"
                } else {
                    "other"
                }
                .to_string();
                match &last_role {
                    None => {
                        telemetry.send(TelemetryEvent::NodeStarted {
                            node: config.private_domain.clone(),
                            role: role.clone(),
                        });
                    }
                    Some(prev) if *prev != role => {
                        info!(from = %prev, to = %role, "role changed");
                        telemetry.send(TelemetryEvent::RoleChanged {
                            node: config.private_domain.clone(),
                            old_role: prev.clone(),
                            new_role: role.clone(),
                        });
                    }
                    _ => {}
                }
                last_role = Some(role);
                if h.is_writable_primary {
                    prune_round(&config, &mongo, &telemetry, &mut gone, gone_dwell).await;
                }
            }
            Err(e) => debug!(error = %e, "hello failed in member loop"),
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// On the primary: any member the set cannot reach whose NAME has been
/// NXDOMAIN for the whole dwell is removed from the config. Everything short
/// of that proof (a crash, a partition, a redeploy window) keeps the member.
async fn prune_round(
    config: &Config,
    mongo: &Mongo,
    telemetry: &Telemetry,
    gone: &mut GoneTracker,
    gone_dwell: Duration,
) {
    let Ok(RsStatus::Active { members, .. }) = mongo.rs_status().await else {
        return;
    };
    let now = Instant::now();
    for m in &members {
        if m.is_self {
            continue;
        }
        if m.healthy {
            gone.observe_reachable(&m.host);
            continue;
        }
        let (host, _) = split_host_port(&m.host);
        let (verdict, detail) = probe_name_detailed(&host, Duration::from_secs(2)).await;
        gone.observe(&m.host, verdict, now);
        debug!(member = %m.host, ?verdict, ?detail, "unreachable member probed");
        if !gone.is_waived(&m.host, now, gone_dwell) {
            continue;
        }
        let Ok(current) = mongo.rs_config().await else {
            return;
        };
        match config_with_member_removed(&current, &m.host) {
            Ok(next) => match mongo.rs_reconfig(next).await {
                Ok(()) => {
                    warn!(member = %m.host, "removed a member whose name has been gone for the whole dwell");
                    telemetry.send(TelemetryEvent::ComponentError {
                        component: "mongo-wrapper".to_string(),
                        error: format!(
                            "removed departed member {} from the replica set config",
                            m.host
                        ),
                        context: "membership-prune".to_string(),
                    });
                    gone.observe_reachable(&m.host);
                    // One membership change per round: mongod requires the
                    // previous config to commit before the next.
                    return;
                }
                Err(e) => {
                    warn!(member = %m.host, error = %e, "could not remove departed member; will retry")
                }
            },
            Err(e) => warn!(member = %m.host, error = %e, "refusing to build the pruned config"),
        }
    }
    let _ = config;
}

/// Standalone mode: wait for mongod, then clear any replica set config a
/// previous HA life left behind (see Mongo::drop_stale_replset_config).
pub async fn standalone_duties(config: Arc<Config>, mongo: Mongo, telemetry: Arc<Telemetry>) {
    wait_for_final_mongod(&mongo, &config).await;
    match mongo.drop_stale_replset_config().await {
        Ok(true) => warn!(
            "dropped the replica set config left by a previous HA life (local database); \
             this node runs standalone now"
        ),
        Ok(false) => {}
        Err(e) => {
            error!(error = %e, "could not check/drop a stale replica set config");
            telemetry.send(TelemetryEvent::ComponentError {
                component: "mongo-wrapper".to_string(),
                error: e.to_string(),
                context: "drop_stale_replset_config".to_string(),
            });
        }
    }
    telemetry.send(TelemetryEvent::NodeStarted {
        node: config.private_domain.clone(),
        role: "standalone".to_string(),
    });
}

/// Log a waiting reason once per distinct reason, not once per poll.
fn wait_log_once(last: &mut String, reason: &str) -> bool {
    if last == reason {
        return false;
    }
    *last = reason.to_string();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_set(has_data: bool) -> PeerStanding {
        PeerStanding::NoSet { has_data }
    }

    #[test]
    fn a_live_set_anywhere_means_join_and_prefers_a_known_primary() {
        let peers = vec![
            (
                "mongo-2".to_string(),
                Some(1),
                PeerStanding::InSet { primary_host: None },
            ),
            (
                "mongo-3".to_string(),
                Some(2),
                PeerStanding::InSet {
                    primary_host: Some("mongo-3:27017".into()),
                },
            ),
        ];
        assert_eq!(
            decide(true, Some(0), &peers),
            Verdict::JoinExisting {
                primary_host: Some("mongo-3:27017".into())
            }
        );
        // Even an unreachable third peer does not block joining.
        let mut with_unknown = peers.clone();
        with_unknown.push(("mongo-4".into(), Some(3), PeerStanding::Unknown));
        assert!(matches!(
            decide(false, Some(0), &with_unknown),
            Verdict::JoinExisting { .. }
        ));
    }

    #[test]
    fn an_unanswered_peer_voids_the_round() {
        let peers = vec![
            ("mongo-2".to_string(), Some(1), no_set(false)),
            ("mongo-3".to_string(), Some(2), PeerStanding::Unknown),
        ];
        assert_eq!(decide(true, Some(0), &peers), Verdict::Undecidable);
    }

    #[test]
    fn data_outranks_seed_order() {
        // Root (rank 0) is fresh; mongo-3 holds data: mongo-3 initiates.
        let peers = vec![
            ("mongo-2".to_string(), Some(1), no_set(false)),
            ("mongo-3".to_string(), Some(2), no_set(true)),
        ];
        assert_eq!(
            decide(false, Some(0), &peers),
            Verdict::DeferTo("mongo-3".into())
        );
        // ...and from mongo-3's point of view it is safe.
        let peers = vec![
            ("mongo-1".to_string(), Some(0), no_set(false)),
            ("mongo-2".to_string(), Some(1), no_set(false)),
        ];
        assert_eq!(decide(true, Some(2), &peers), Verdict::SafeToInitiate);
    }

    #[test]
    fn identical_standings_fall_back_to_seed_order() {
        let peers = vec![
            ("mongo-2".to_string(), Some(1), no_set(false)),
            ("mongo-3".to_string(), Some(2), no_set(false)),
        ];
        assert_eq!(decide(false, Some(0), &peers), Verdict::SafeToInitiate);
        let peers = vec![
            ("mongo-1".to_string(), Some(0), no_set(false)),
            ("mongo-3".to_string(), Some(2), no_set(false)),
        ];
        assert_eq!(
            decide(false, Some(1), &peers),
            Verdict::DeferTo("mongo-1".into())
        );
    }

    #[test]
    fn undeclared_peers_and_self_rank_last() {
        // A scaled-in peer not in our seeds never wins a tie against us...
        let peers = vec![("mongo-9".to_string(), None, no_set(false))];
        assert_eq!(decide(false, Some(0), &peers), Verdict::SafeToInitiate);
        // ...but a node that cannot find itself in the seeds defers to any
        // declared peer.
        let peers = vec![("mongo-1".to_string(), Some(0), no_set(false))];
        assert_eq!(
            decide(false, None, &peers),
            Verdict::DeferTo("mongo-1".into())
        );
    }

    #[test]
    fn no_peers_declared_is_safe_to_initiate() {
        assert_eq!(decide(false, Some(0), &[]), Verdict::SafeToInitiate);
    }

    #[test]
    fn gone_tracker_requires_a_continuous_proof() {
        let mut t = GoneTracker::new();
        let start = Instant::now();
        let dwell = Duration::from_secs(60);
        t.observe("mongo-2", NameVerdict::Gone, start);
        assert!(!t.is_waived("mongo-2", start + Duration::from_secs(30), dwell));
        assert!(t.is_waived("mongo-2", start + Duration::from_secs(60), dwell));
        // Any non-Gone observation resets the clock.
        t.observe(
            "mongo-2",
            NameVerdict::ExistsOrUnknown,
            start + Duration::from_secs(61),
        );
        assert!(!t.is_waived("mongo-2", start + Duration::from_secs(200), dwell));
        t.observe(
            "mongo-2",
            NameVerdict::Gone,
            start + Duration::from_secs(200),
        );
        t.observe_reachable("mongo-2");
        assert!(!t.is_waived("mongo-2", start + Duration::from_secs(1000), dwell));
    }

    #[test]
    fn standing_maps_answers() {
        let state = |set_active, has_data| RsState {
            node_id: "x:27017".into(),
            set_active,
            set_name: None,
            my_state: None,
            is_primary: false,
            primary_host: None,
            members: vec![],
            members_total: 0,
            members_healthy: 0,
            has_data,
            config_version: None,
        };
        assert_eq!(
            standing_of(&PeerAnswer::State(state(true, true))),
            PeerStanding::InSet { primary_host: None }
        );
        assert_eq!(
            standing_of(&PeerAnswer::State(state(false, true))),
            PeerStanding::NoSet { has_data: true }
        );
        assert_eq!(standing_of(&PeerAnswer::NotReady), PeerStanding::Unknown);
        assert_eq!(standing_of(&PeerAnswer::Unreachable), PeerStanding::Unknown);
    }

    #[test]
    fn wait_log_once_dedupes_by_reason() {
        let mut last = String::new();
        assert!(wait_log_once(&mut last, "a"));
        assert!(!wait_log_once(&mut last, "a"));
        assert!(wait_log_once(&mut last, "b"));
    }
}
