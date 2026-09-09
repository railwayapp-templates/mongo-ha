//! HTTP health server embedded in each MongoDB node.
//!
//! Three probe endpoints, all fail-closed (any error, timeout, or uncertain
//! read answers 503), plus one action endpoint the Railway dashboard drives:
//!
//!   GET /health — liveness: 200 iff mongod answers `ping`.
//!   GET /role   — write-routing fence: 200 iff this node is the replica set
//!                 PRIMARY AND its own view of the set has a reachable
//!                 majority. HAProxy's write frontend routes exclusively on
//!                 this. In standalone mode (no RS_SEEDS) it degrades to
//!                 liveness: a lone node is trivially its own primary.
//!   GET /rs/state — peer exchange (JSON, see peers::RsState): whether this
//!                 node holds a set, who its primary is, whether it holds user
//!                 data. 503 until the FINAL mongod answers, so a peer
//!                 mid-boot reads as "not ready", never as "empty and free".
//!   POST /rs/keyfile — hand the set's keyfile to the ROOT account: the caller
//!                 sends the root username and password, this node
//!                 authenticates them against its own mongod and confirms the
//!                 session holds the `root` role (`connectionStatus`). How a
//!                 fresh member joins after the environment's RS_KEY drifted
//!                 from what the set runs with (see auth_pin.rs).
//!   POST /switchover — ask THIS node to become the primary (the generic
//!                 clusterWiring.dataNodeSwitchover contract). Freezes every
//!                 other secondary, steps the current primary down with a
//!                 catch-up window, and waits for this node to win the
//!                 election; 200 means it did (which /role then reflects).

use crate::config::Config;
use crate::mongo::{has_majority, probe_root, Mongo, RootProbe, RsStatus};
use crate::rs::local_rs_state;
use anyhow::Context;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use common::{Telemetry, TelemetryEvent};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

pub struct AppState {
    pub mongo: Mongo,
    pub config: Arc<Config>,
    pub standalone: bool,
    /// The keyfile content this node's mongod runs with (None standalone).
    pub keyfile: Option<Arc<String>>,
    /// Whether the data dir held data at boot — see rs::local_rs_state.
    pub has_data: bool,
}

#[derive(Deserialize)]
struct KeyfileRequest {
    username: String,
    password: String,
}

/// At most this many /rs/keyfile credential checks run at once, and every
/// refusal keeps its slot for KEYFILE_REFUSAL_DELAY before answering. The
/// exchange answers with the `__system` credential, so guessing at it through
/// this route must cost at least what guessing at mongod's own port does. A
/// caller with the right credential never waits on the delay, and the cap is
/// far above the handful of members a set boots at once.
static KEYFILE_PROBES: Semaphore = Semaphore::const_new(4);
const KEYFILE_REFUSAL_DELAY: Duration = Duration::from_secs(1);

/// The set's keyfile, to the root account only: the request must name the
/// configured root username, the password must authenticate against this
/// node's own mongod, and the authenticated session must hold `root` on
/// `admin`. 401 otherwise, 503 while mongod cannot judge, 404 on a standalone
/// node (there is no set to join). The probe runs against the local mongod, so
/// it follows the password the set actually enforces (the pin's), never the
/// environment variable.
async fn rs_keyfile(
    State(state): State<Arc<AppState>>,
    Json(req): Json<KeyfileRequest>,
) -> impl IntoResponse {
    let Some(keyfile) = state.keyfile.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            "not a replica set member".to_string(),
        );
    };
    // Nothing closes the semaphore; a closed one is treated like "cannot
    // judge" rather than a panic inside a request handler.
    let Ok(_slot) = KEYFILE_PROBES.acquire().await else {
        return keyfile_reply(keyfile, &RootProbe::NotReady("probe slots closed".into()));
    };
    // Any other account is refused before mongod is even asked: the exchange
    // is for the root account, and a valid password for some other user must
    // not be probed on its behalf.
    let probe = if req.username == state.config.mongo_root_username {
        probe_root(
            "127.0.0.1",
            state.config.mongo_port,
            &req.username,
            &req.password,
        )
        .await
    } else {
        RootProbe::Refused
    };
    match &probe {
        RootProbe::Root => {}
        RootProbe::Refused => {
            warn!("refused a /rs/keyfile request: not the root account");
            tokio::time::sleep(KEYFILE_REFUSAL_DELAY).await;
        }
        RootProbe::NotReady(e) => {
            warn!(error = %e, "/rs/keyfile: mongod could not judge the credential")
        }
    }
    keyfile_reply(keyfile, &probe)
}

/// What /rs/keyfile answers for a probe outcome. The bodies are fixed strings:
/// a refusal does not say which of username, password or role failed, and the
/// 503 keeps the driver's error text for the log (see rs_keyfile) rather than
/// relaying it to a remote caller.
fn keyfile_reply(keyfile: &str, probe: &RootProbe) -> (StatusCode, String) {
    match probe {
        RootProbe::Root => (StatusCode::OK, keyfile.to_string()),
        RootProbe::Refused => (
            StatusCode::UNAUTHORIZED,
            "authentication failed".to_string(),
        ),
        RootProbe::NotReady(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "mongod not ready".to_string(),
        ),
    }
}

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.mongo.ping().await {
        Ok(()) => (StatusCode::OK, "ok"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "mongod not answering"),
    }
}

async fn role(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.standalone {
        // No set to fence against — alive means writable.
        return match state.mongo.ping().await {
            Ok(()) => (StatusCode::OK, "primary (standalone)"),
            Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "mongod not answering"),
        };
    }

    let verdict = async {
        let hello = state.mongo.hello().await?;
        if !hello.is_writable_primary {
            return anyhow::Ok(false);
        }
        // mongod steps a primary down on its own once it loses the majority,
        // but only after its election timeout; answering 503 the moment our
        // own view lacks a majority pulls the node from write rotation ahead
        // of that.
        match state.mongo.rs_status().await? {
            RsStatus::Active { members, .. } => anyhow::Ok(has_majority(&members)),
            RsStatus::NotInitialized => anyhow::Ok(false),
        }
    }
    .await;

    match verdict {
        Ok(true) => (StatusCode::OK, "primary"),
        Ok(false) => (StatusCode::SERVICE_UNAVAILABLE, "not primary"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "state unavailable"),
    }
}

async fn rs_state(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // The entrypoint's init temp server answers `hello` too — but it is not
    // the server whose state peers must reason about. Refuse until the final
    // one (the one running with --replSet) is up.
    match state.mongo.hello().await {
        Ok(h) if !state.standalone && !h.replication_enabled() => {
            return (StatusCode::SERVICE_UNAVAILABLE, "mongod initializing").into_response();
        }
        Ok(_) => {}
        Err(_) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "mongod not answering").into_response();
        }
    }
    match local_rs_state(&state.mongo, &state.config, state.has_data).await {
        Ok(s) => (StatusCode::OK, Json(s)).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "state unavailable").into_response(),
    }
}

/// How long the other secondaries are kept out of the election, and how
/// long the stepping-down primary refuses to seek re-election.
const FREEZE_SECS: i64 = 30;
/// How long the primary waits for THIS node to catch up before stepping
/// down — the handoff's data-safety window.
const CATCHUP_SECS: i64 = 10;
const SWITCHOVER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(45);
const PROMOTION_POLL: std::time::Duration = std::time::Duration::from_millis(500);

/// Promote this node. mongod has no "make member X primary" primitive; the
/// documented equivalent is to freeze every other electable secondary, step
/// the primary down with a catch-up period, and let the one unfrozen
/// secondary win — which is exactly what runs here. Freezes are undone at the
/// end whichever way it went (and expire on their own regardless).
async fn switchover(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.standalone {
        return match state.mongo.ping().await {
            Ok(()) => (StatusCode::OK, "already primary (standalone)".to_string()),
            Err(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "mongod not answering".to_string(),
            ),
        };
    }

    let outcome = tokio::time::timeout(SWITCHOVER_DEADLINE, async {
        let hello = state.mongo.hello().await?;
        if hello.is_writable_primary {
            return anyhow::Ok(true);
        }
        let RsStatus::Active { members, .. } = state.mongo.rs_status().await? else {
            anyhow::bail!("this node is not a replica set member");
        };
        let primary_host = members
            .iter()
            .find(|m| m.state == crate::mongo::states::PRIMARY)
            .map(|m| m.host.clone())
            .or(hello.primary)
            .context("no primary to hand off from")?;
        let me = state.config.node_id();
        let others: Vec<String> = members
            .iter()
            .filter(|m| !m.is_self && !m.host.eq_ignore_ascii_case(&primary_host))
            .filter(|m| !m.host.eq_ignore_ascii_case(&me))
            .map(|m| m.host.clone())
            .collect();

        let member = |host: &str| {
            Mongo::connect_member(
                host,
                &state.config.mongo_root_username,
                &state.config.mongo_root_password,
            )
        };
        for host in &others {
            if let Err(e) = member(host).freeze(FREEZE_SECS).await {
                warn!(%host, error = %format!("{e:#}"), "could not freeze a secondary; it may win the election instead");
            }
        }

        let primary = member(&primary_host);
        let step = async {
            loop {
                match primary.step_down(FREEZE_SECS, CATCHUP_SECS).await {
                    Ok(()) => return anyhow::Ok(()),
                    Err(e) if crate::mongo::command_error_code(&e)
                        == Some(crate::mongo::codes::EXCEEDED_TIME_LIMIT) =>
                    {
                        info!("primary waited out the catch-up window; retrying the step-down");
                    }
                    Err(e) => return Err(e),
                }
            }
        };
        let stepped = step.await;

        // Wait for this node to take over, then lift the freezes either way.
        let promoted = async {
            loop {
                if let Ok(h) = state.mongo.hello().await {
                    if h.is_writable_primary {
                        return true;
                    }
                }
                tokio::time::sleep(PROMOTION_POLL).await;
            }
        };
        let won = match stepped {
            Ok(()) => {
                tokio::time::timeout(std::time::Duration::from_secs(20), promoted)
                    .await
                    .unwrap_or(false)
            }
            Err(e) => {
                warn!(error = %format!("{e:#}"), "step-down refused");
                false
            }
        };
        for host in &others {
            if let Err(e) = member(host).freeze(0).await {
                warn!(%host, error = %format!("{e:#}"), "could not unfreeze a secondary (the freeze expires on its own)");
            }
        }
        if !won {
            anyhow::bail!("this node did not become primary after the step-down");
        }
        anyhow::Ok(false)
    })
    .await;

    match outcome {
        Ok(Ok(true)) => (StatusCode::OK, "already primary".to_string()),
        Ok(Ok(false)) => {
            info!("switchover complete: this node is now the primary");
            (StatusCode::OK, "switchover complete".to_string())
        }
        Ok(Err(e)) => {
            warn!(error = %format!("{e:#}"), "switchover refused");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("switchover refused: {e:#}"),
            )
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("switchover timed out after {SWITCHOVER_DEADLINE:?}"),
        ),
    }
}

async fn run_health_server(health_port: u16, state: Arc<AppState>) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/role", get(role))
        .route("/rs/state", get(rs_state))
        .route("/rs/keyfile", post(rs_keyfile))
        .route("/switchover", post(switchover))
        .with_state(state);

    // Bind the IPv6 unspecified address rather than 0.0.0.0: Railway's private
    // network is IPv6 (fd12::... hostnames), and an IPv4-only listener refuses
    // every connection HAProxy's health check makes over it. Linux dual-stack
    // sockets accept IPv4-mapped connections on the same listener by default.
    let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], health_port));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("health server bind failed")?;
    info!(port = health_port, "health server listening");

    axum::serve(listener, app)
        .await
        .context("health server exited")?;
    Ok(())
}

// A run that stayed up at least this long was healthy in between — the next
// failure is a new incident, not a continuation of the same crash loop, and
// earns its own telemetry event. Same thresholds as redis-ha's supervisor.
const HEALTHY_RUN_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(60);
const RESPAWN_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// Run the health server FOREVER, rebinding after any failure. This server is
/// the node's entire external interface — HAProxy's routing probe and every
/// peer's initiate-guard query go through it — so a dead server makes the
/// node invisible. Each attempt runs in its own spawned task so a PANIC
/// surfaces as a caught JoinError instead of killing this supervision loop,
/// and telemetry is deduped per incident via HEALTHY_RUN_THRESHOLD.
pub async fn run_health_server_supervised(
    health_port: u16,
    state: Arc<AppState>,
    telemetry: Arc<Telemetry>,
) {
    let mut alerted_for_current_incident = false;

    loop {
        let attempt_state = state.clone();
        let started_at = std::time::Instant::now();
        let handle =
            tokio::task::spawn(async move { run_health_server(health_port, attempt_state).await });
        let outcome = handle.await;
        let ran_for = started_at.elapsed();

        let failure = match outcome {
            Ok(Ok(())) => {
                error!("health server returned unexpectedly; restarting");
                "run loop returned cleanly".to_string()
            }
            Ok(Err(e)) => {
                error!(error = %format!("{e:#}"), "health server failed; restarting");
                format!("bind/serve failed: {e:#}")
            }
            Err(e) if e.is_panic() => {
                error!(panic = ?e, "health server panicked; restarting");
                "task panicked".to_string()
            }
            Err(e) => {
                error!(error = %format!("{e:#}"), "health server task was cancelled; restarting");
                "task cancelled".to_string()
            }
        };

        if ran_for >= HEALTHY_RUN_THRESHOLD {
            alerted_for_current_incident = false;
        }
        if !alerted_for_current_incident {
            alerted_for_current_incident = true;
            telemetry.send(TelemetryEvent::ComponentError {
                component: "mongo-wrapper".to_string(),
                error: failure,
                context: "health_server".to_string(),
            });
        }

        tokio::time::sleep(RESPAWN_DELAY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn config(mongo_port: u16) -> Config {
        Config {
            mongo_root_username: "mongo".into(),
            mongo_root_password: "pw".into(),
            mongo_port,
            rs_enabled_flag: true,
            rs_seeds: Some("mongo-1:27017,mongo-2:27017,mongo-3:27017".into()),
            rs_name: "rs0".into(),
            rs_key: Some("k".into()),
            keyfile_path: "/run/mongo-ha/keyfile".into(),
            health_port: 8080,
            private_domain: "mongo-1".into(),
            data_dir: "/data/db".into(),
            peer_query_timeout_ms: 2000,
            bootstrap_dwell_seconds: 15,
            demote_timeout_ms: 20_000,
            peer_gone_dwell_seconds: 1800,
        }
    }

    /// A loopback port nothing listens on: bound, read, released.
    async fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    /// The keyfile route alone, served on a loopback port for the test's life.
    async fn serve(state: Arc<AppState>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/rs/keyfile", post(rs_keyfile))
            .with_state(state);
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/rs/keyfile")
    }

    fn member_state(mongo_port: u16, keyfile: Option<&str>) -> Arc<AppState> {
        Arc::new(AppState {
            mongo: Mongo::connect_local(mongo_port, "mongo", "pw"),
            config: Arc::new(config(mongo_port)),
            standalone: keyfile.is_none(),
            keyfile: keyfile.map(|k| Arc::new(k.to_string())),
            has_data: false,
        })
    }

    #[test]
    fn keyfile_reply_hands_the_keyfile_only_to_root() {
        let (status, body) = keyfile_reply("KEY==", &RootProbe::Root);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "KEY==");

        let (status, body) = keyfile_reply("KEY==", &RootProbe::Refused);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, "authentication failed");
    }

    #[test]
    fn keyfile_reply_keeps_driver_errors_out_of_the_body() {
        let driver_text = "Kind: I/O error: Connection refused (os error 111), labels: {}";
        let (status, body) = keyfile_reply("KEY==", &RootProbe::NotReady(driver_text.into()));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "mongod not ready");
    }

    /// The username gate runs BEFORE mongod is asked: with no mongod at all
    /// on the configured port, a non-root username is still refused (401),
    /// while the root username reaches the probe and gets the fixed 503.
    #[tokio::test]
    async fn keyfile_route_refuses_a_non_root_username_before_asking_mongod() {
        let port = closed_port().await;
        let url = serve(member_state(port, Some("KEY=="))).await;
        let client = reqwest::Client::new();

        let resp = client
            .post(&url)
            .json(&serde_json::json!({ "username": "reader", "password": "pw" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        assert_eq!(resp.text().await.unwrap(), "authentication failed");

        let resp = client
            .post(&url)
            .json(&serde_json::json!({ "username": "mongo", "password": "pw" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 503);
        assert_eq!(resp.text().await.unwrap(), "mongod not ready");
    }

    #[tokio::test]
    async fn keyfile_route_is_404_on_a_standalone_node() {
        let port = closed_port().await;
        let url = serve(member_state(port, None)).await;
        let resp = reqwest::Client::new()
            .post(&url)
            .json(&serde_json::json!({ "username": "mongo", "password": "pw" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }
}
