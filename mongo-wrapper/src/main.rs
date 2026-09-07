//! Entrypoint for the MongoDB replica set node container.
//!
//! Boot sequence (HA mode, RS_SEEDS set):
//!   1. Parse config; take the volume runtime lock.
//!   2. Derive the keyfile from RS_KEY and write it (keyfile.rs) — BEFORE
//!      mongod spawns, since `--keyFile` points at it.
//!   3. Start the health server (/health, /role, /rs/state, /switchover) —
//!      fail-closed until mongod answers.
//!   4. Spawn `docker-entrypoint.sh mongod --replSet ... --keyFile ...` (args
//!      passed through) and supervise it: the container lives and dies with
//!      mongod.
//!   5. In the background, run the orchestrator: wait for the final mongod,
//!      then join the existing set if any peer holds one, else — only with
//!      every peer answering, only when this node holds the data (or wins
//!      the seed-order tie), and only after a dwell — initiate a new set.
//!
//! Standalone mode (RS_SEEDS unset or RS_ENABLED=false): mongod boots with no
//! `--replSet` — exactly as the upstream image would — with /health as a real
//! liveness probe and /role answering 200 while mongod is alive. A replica
//! set config left on the volume by a previous HA life is dropped, the
//! documented way, so a later re-conversion starts from a clean initiate.
//! This is the state a reverted (HA → standalone) service runs in while it
//! still uses this image.

mod auth_pin;
mod config;
mod demote_on_shutdown;
mod dns_probe;
mod health_server;
mod keyfile;
mod mongo;
mod peers;
mod process_manager;
mod rs;
mod volume_lock;

use anyhow::Result;
use common::{init_logging, Telemetry, TelemetryEvent};
use config::Config;
use health_server::AppState;
use std::sync::Arc;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = init_logging("mongo-wrapper");

    let config = Arc::new(Config::from_env()?);
    let telemetry = Arc::new(Telemetry::from_env("mongo-ha"));

    // At most one container runs against this dataset at a time: wait for a
    // previous container's supervisor to release the volume before anything
    // below touches the data directory (see volume_lock). Fail-stop on
    // timeout — the restart policy retries the boot. A lock file that cannot
    // be opened keeps the documented fail-open boot, but the lost overlap
    // protection is reported, not just warned.
    match volume_lock::acquire_volume_runtime_lock(&config.data_dir)? {
        volume_lock::VolumeLockOutcome::Held => {}
        volume_lock::VolumeLockOutcome::FailedOpen => {
            let error = format!(
                "could not open the runtime lock file under {}; booting WITHOUT the volume \
                 lock — if a previous container is still alive on this volume, two mongod \
                 engines may now touch the same dbpath",
                config.data_dir
            );
            tracing::error!("{error}");
            telemetry.send_once(TelemetryEvent::ComponentError {
                component: "volume-lock".to_string(),
                error,
                context: "startup".to_string(),
            });
        }
    }

    info!(
        mongo_port = config.mongo_port,
        health_port = config.health_port,
        rs_enabled = config.rs_enabled(),
        rs_name = %config.rs_name,
        node = %config.node_id(),
        "starting mongo-wrapper"
    );

    // Decided before anything spawns: a data dir that already holds a mongod
    // dataset is an adopted volume (or a returning member) and outranks fresh
    // nodes in the initiate tie-break. Asking the running server instead is
    // impossible on a not-yet-initiated replica set member (reads refused).
    let has_data = config.datadir_is_initialized();
    info!(has_data, "data directory inspected");

    // Credentials for this boot: the volume's pin outranks the environment
    // (see auth_pin.rs). A node with no pin that finds a live set among its
    // peers adopts that set's keyfile instead of deriving its own.
    let pin = auth_pin::read_pin(&config.data_dir);
    if pin.is_none()
        && std::path::Path::new(&config.data_dir)
            .join(auth_pin::PIN_FILE)
            .exists()
    {
        warn!("credential pin exists but does not parse; running on the environment's values");
    }
    let live_set_keyfile =
        if config.rs_enabled() && pin.as_ref().is_none_or(|p| p.keyfile.is_none()) {
            rs::discover_live_set_keyfile(&config).await
        } else {
            None
        };
    let creds = auth_pin::resolve_boot_credentials(
        pin.as_ref(),
        &config.mongo_root_password,
        config
            .rs_enabled()
            .then_some(config.rs_key.as_deref())
            .flatten(),
        live_set_keyfile.as_deref(),
    );
    if creds.env_drifted {
        // Reported again, with the verdict, by the resolver once mongod
        // answers; this is the boot-time heads-up.
        warn!(
            "the environment's root password / RS_KEY differ from this volume's credential pin; \
             booting on the pinned values (the variables only initialize a fresh data dir)"
        );
    }

    let mongo = mongo::Mongo::connect_local(
        config.mongo_port,
        &config.mongo_root_username,
        &creds.password,
    );

    // Flags this wrapper owns, ahead of any CLI args passed through. The
    // upstream entrypoint strips --replSet/--keyFile/--auth for its one-time
    // init server and restores them for the real one.
    let mut flags: Vec<String> = vec![
        "--bind_ip_all".to_string(),
        // Railway's private network is IPv6-only; without this mongod binds
        // IPv4 only and no peer can reach it.
        "--ipv6".to_string(),
        "--port".to_string(),
        config.mongo_port.to_string(),
    ];
    if config.data_dir != "/data/db" {
        flags.push("--dbpath".to_string());
        flags.push(config.data_dir.clone());
    }

    if config.rs_enabled() {
        let keyfile = creds
            .keyfile
            .clone()
            .expect("HA mode always resolves a keyfile (RS_KEY is validated in Config::from_env)");
        keyfile::write_keyfile_content(&config.keyfile_path, &keyfile)?;
        flags.extend([
            "--replSet".to_string(),
            config.rs_name.clone(),
            "--keyFile".to_string(),
            config.keyfile_path.clone(),
        ]);

        tokio::spawn(health_server::run_health_server_supervised(
            config.health_port,
            Arc::new(AppState {
                mongo: mongo.clone(),
                config: config.clone(),
                standalone: false,
                keyfile: Some(Arc::new(keyfile)),
                has_data,
            }),
            telemetry.clone(),
        ));
        tokio::spawn(rs::orchestrate(
            config.clone(),
            mongo.clone(),
            telemetry.clone(),
            has_data,
        ));
    } else {
        info!("RS_SEEDS not set (or RS_ENABLED=false) — standalone passthrough mode");
        tokio::spawn(health_server::run_health_server_supervised(
            config.health_port,
            Arc::new(AppState {
                mongo: mongo.clone(),
                config: config.clone(),
                standalone: true,
                keyfile: None,
                has_data,
            }),
            telemetry.clone(),
        ));
        tokio::spawn(rs::standalone_duties(
            config.clone(),
            mongo.clone(),
            telemetry.clone(),
        ));
    }

    // Proves the boot credentials against the live server, writes the pin,
    // and follows a properly rotated password (see auth_pin::resolver).
    tokio::spawn(auth_pin::resolver(
        config.data_dir.clone(),
        config.mongo_root_password.clone(),
        creds.clone(),
        mongo.clone(),
        telemetry.clone(),
    ));

    // MONGO_INITDB_ROOT_USERNAME/PASSWORD reach docker-entrypoint.sh through
    // the inherited process environment, not as CLI args.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let child = process_manager::spawn_mongod(&flags, &args).await?;

    // HA mode: hand the primary role off before mongod is signaled, so a
    // planned shutdown is a step-down with catch-up, not a detection-timeout
    // failover.
    let demote = config.rs_enabled().then(|| demote_on_shutdown::DemoteCtx {
        mongo: mongo.clone(),
        deadline_ms: config.demote_timeout_ms,
    });

    process_manager::supervise(child, demote).await
}
