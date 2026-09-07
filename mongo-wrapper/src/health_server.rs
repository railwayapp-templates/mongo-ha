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
//!   POST /rs/keyfile — hand the set's keyfile to a node that proves the root
//!                 password (verified against this node's own mongod). How a
//!                 fresh member joins after the environment's RS_KEY drifted
//!                 from what the set runs with (see auth_pin.rs).
//!   POST /switchover — ask THIS node to become the primary (the generic
//!                 clusterWiring.dataNodeSwitchover contract). Freezes every
//!                 other secondary, steps the current primary down with a
//!                 catch-up window, and waits for this node to win the
//!                 election; 200 means it did (which /role then reflects).

use crate::config::Config;
use crate::mongo::{has_majority, probe_password, Mongo, PasswordProbe, RsStatus};
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
use tracing::{error, info, warn};

pub struct AppState {
    pub mongo: Mongo,
    pub config: Arc<Config>,
    pub standalone: bool,
    /// The keyfile content this node's mongod runs with (None standalone).
    pub keyfile: Option<Arc<String>>,
}

#[derive(Deserialize)]
struct KeyfileRequest {
    username: String,
    password: String,
}

/// The set's keyfile, to a caller that proves the root password against this
/// node's own mongod. 401 on a wrong password, 503 while mongod cannot judge,
/// 404 on a standalone node (there is no set to join).
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
    match probe_password(
        "127.0.0.1",
        state.config.mongo_port,
        &req.username,
        &req.password,
    )
    .await
    {
        PasswordProbe::Works => (StatusCode::OK, keyfile.to_string()),
        PasswordProbe::AccessDenied => {
            warn!("refused a /rs/keyfile request: authentication failed");
            (
                StatusCode::UNAUTHORIZED,
                "authentication failed".to_string(),
            )
        }
        PasswordProbe::NotReady(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("mongod not ready: {e}"),
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
    match local_rs_state(&state.mongo, &state.config).await {
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
                warn!(%host, error = %e, "could not freeze a secondary; it may win the election instead");
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
                warn!(error = %e, "step-down refused");
                false
            }
        };
        for host in &others {
            if let Err(e) = member(host).freeze(0).await {
                warn!(%host, error = %e, "could not unfreeze a secondary (the freeze expires on its own)");
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
            warn!(error = %e, "switchover refused");
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
                error!(error = %e, "health server failed; restarting");
                format!("bind/serve failed: {e:#}")
            }
            Err(e) if e.is_panic() => {
                error!(panic = ?e, "health server panicked; restarting");
                "task panicked".to_string()
            }
            Err(e) => {
                error!(error = %e, "health server task was cancelled; restarting");
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
