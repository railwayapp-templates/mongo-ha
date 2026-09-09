//! Replay the oplog before a replica set volume boots as a standalone.
//!
//! ## Why a `--replSet`-less boot loses writes
//!
//! A replica set member does not journal its collections. Durability comes
//! from the journaled oplog plus periodic *stable* checkpoints (every 60s by
//! default), and every boot with `--replSet` replays the oplog from the last
//! stable checkpoint to its top before serving — that replay IS the member's
//! crash recovery. A boot WITHOUT `--replSet` on the same data dir performs no
//! replay at all: on a standalone, `ReplicationCoordinatorImpl::startup` runs
//! replication recovery only under the `recoverFromOplogAsStandalone` server
//! parameter. The storage engine then reconciles its tables against the
//! checkpointed catalog and drops every collection and index created after
//! that checkpoint as an "unknown ident" (`StorageEngineImpl::
//! reconcileCatalogAndIdents`, log id 22251); documents written after it into
//! older collections are simply not there. mongod says as much at startup
//! (log id 20547: "Document(s) exist in 'system.replset', but started without
//! --replSet. Database contents may appear inconsistent with the writes that
//! were visible when this node was running as part of a replica set").
//!
//! The revert flow boots the root standalone on its HA volume. After a crash
//! before the redeploy (SIGKILL, OOM, host loss) up to a checkpoint interval
//! of acknowledged writes is lost that way, silently — CI reproduced it on
//! every run (`docker rm -f` on the root; the standalone boot logged 22251 for
//! every collection of the test database and the canary was gone). A clean
//! stop checkpoints at the stable timestamp, so it keeps majority-committed
//! writes but still loses whatever the primary acknowledged past the majority
//! commit point.
//!
//! ## The recovery boot
//!
//! mongod ships the tool for exactly this. Before the real standalone mongod,
//! the wrapper runs one more on the loopback with
//! `--setParameter recoverFromOplogAsStandalone=true`: it performs replication
//! recovery as a standalone — the same replay a `--replSet` boot would run —
//! and refuses user writes while it is up (`disallowUserWrites`). With
//! `--setParameter takeUnstableCheckpointOnShutdown=true` its clean shutdown
//! checkpoints everything it holds instead of only the stable timestamp
//! (`WiredTigerKVEngine::cleanShutdown`: `use_timestamp=false`), so the
//! replayed state is on disk before the real mongod opens the data dir and
//! reconciles it. Both are startup-only server parameters of MongoDB 8.0
//! (`repl_server_parameters.idl`, `storage_parameters.idl`); the manual does
//! not document them, the server source does. The sequence is idempotent:
//! interrupted before its shutdown, the next boot replays again.
//!
//! ## When it runs
//!
//! Standalone mode, on a data dir that holds a dataset, when the volume's
//! credential pin carries a keyfile — a keyfile is pinned only by an HA boot,
//! so it is the wrapper's own record that this dataset ran as a set member.
//! The signal cannot come from the data dir itself (WiredTiger files are
//! opaque) and must not be guessed: on a volume that only ever ran standalone
//! there is no oplog, and the recovery boot is fatal there (log id 31364,
//! "Recovery not possible, no oplog found"). Once the real standalone mongod
//! has proven the password, the resolver re-pins without a keyfile, so the
//! replay runs exactly once per revert.
//!
//! ## When it cannot
//!
//! A recovery mongod that exits before accepting connections with 31364 has
//! found no oplog: an HA volume whose set never formed, nothing replicated to
//! lose — the real boot proceeds. Any other exit stops the node with the fix
//! in its log (exit code 78): the data dir is untouched, and booting it
//! standalone anyway would drop the un-checkpointed collections for good.

use crate::auth_pin::AuthPin;
use crate::config::Config;
use crate::process_manager;
use anyhow::{anyhow, bail, Context, Result};
use mongodb::bson::doc;
use mongodb::options::{ClientOptions, ServerAddress};
use mongodb::Client;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdout};
use tracing::info;

/// mongod's fatal assertion when `recoverFromOplogAsStandalone` finds no oplog
/// to replay ("Recovery not possible, no oplog found",
/// `ReplicationRecoveryImpl::_assertNoRecoveryNeededOnUnstableCheckpoint`).
pub const NO_OPLOG_LOG_ID: i32 = 31364;

/// Exit code when the recovery boot fails for any other reason: EX_CONFIG —
/// the service's variables ask for a standalone boot this volume cannot
/// safely give. Non-zero so the deployment reads as failed and the restart
/// policy retries once the operator has acted.
pub const RECOVERY_FAIL_EXIT_CODE: i32 = 78;

const POLL: Duration = Duration::from_secs(1);
const PROGRESS_EVERY: Duration = Duration::from_secs(30);
/// The shutdown checkpoint writes everything the replay produced — minutes on
/// a large dataset — and interrupting it would discard the replay, so the
/// bound is generous and nothing is ever killed before it.
const SHUTDOWN_LIMIT: Duration = Duration::from_secs(30 * 60);

/// Whether this standalone boot must replay the oplog first. `has_data`: the
/// data dir holds a mongod dataset (decided before anything spawns, see
/// main.rs). `pin`: the volume's credential pin; a keyfile is pinned only by
/// an HA boot, so it is the record that the dataset ran as a set member.
pub fn replay_needed(has_data: bool, pin: Option<&AuthPin>) -> bool {
    has_data && pin.is_some_and(|p| p.keyfile.is_some())
}

/// The mongod flags of the recovery boot. Loopback only: the server is
/// read-only and mid-recovery, nothing outside this container may take it for
/// the database. Same port and dbpath as the real boot, so the wrapper's own
/// client reaches it and the entrypoint's ownership fix-up and
/// already-initialized check see the same directory. The caller appends the
/// container's own CLI args, so storage options given there apply to both
/// boots.
pub fn recovery_flags(config: &Config) -> Vec<String> {
    let mut flags: Vec<String> = vec![
        "--bind_ip".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        config.mongo_port.to_string(),
    ];
    if config.data_dir != "/data/db" {
        flags.push("--dbpath".to_string());
        flags.push(config.data_dir.clone());
    }
    flags.extend(
        [
            "--setParameter",
            "recoverFromOplogAsStandalone=true",
            "--setParameter",
            "takeUnstableCheckpointOnShutdown=true",
        ]
        .map(String::from),
    );
    flags
}

/// How the recovery boot ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// The replay ran and a clean shutdown checkpointed its state: the data
    /// dir holds every write the oplog held.
    Replayed,
    /// No oplog on the volume: the set never formed on it, nothing replicated
    /// was ever written. The real boot proceeds.
    NoOplog,
}

/// The `id` of a mongod JSON log line, if the line is one.
pub fn mongod_log_id(line: &str) -> Option<i32> {
    let rest = line.split_once("\"id\":")?.1;
    let digits: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// A mongod JSON log line at severity F (fatal).
pub fn is_fatal_line(line: &str) -> bool {
    line.contains("\"s\":\"F\"")
}

/// Verdict for a recovery mongod that exited before it accepted connections.
pub fn early_exit_verdict(
    saw_no_oplog: bool,
    code: Option<i32>,
    last_fatal: Option<&str>,
) -> Result<Replay> {
    if saw_no_oplog {
        return Ok(Replay::NoOplog);
    }
    Err(anyhow!(recovery_failed_guidance(code, last_fatal)))
}

/// The customer-facing reason a node stops when the recovery boot fails.
/// Names the state of the volume, why the node does not go on, and the fix.
pub fn recovery_failed_guidance(code: Option<i32>, last_fatal: Option<&str>) -> String {
    let exit = match code {
        Some(code) => format!("exited with code {code}"),
        None => "was killed by a signal".to_string(),
    };
    let fatal = last_fatal
        .map(|l| format!("; its last fatal line: {l}"))
        .unwrap_or_default();
    format!(
        "the replica set volume could not be recovered for a standalone boot: the recovery mongod \
         (recoverFromOplogAsStandalone) {exit} before it came up{fatal}. The data \
         directory is unchanged. Booting it standalone without that replay would drop every \
         collection and index created after its last checkpoint and lose the writes after it, so \
         this node stops here. Fix: re-enable HA on this service (RS_ENABLED=true with its previous \
         RS_SEEDS and RS_KEY) so mongod boots the volume as a replica set member and recovers it \
         itself, then revert again once it is up. A volume that fails here again needs a restore \
         from a backup."
    )
}

/// What the recovery mongod wrote, as far as the verdict needs it.
#[derive(Default)]
struct Observed {
    saw_no_oplog: AtomicBool,
    last_fatal: Mutex<Option<String>>,
}

impl Observed {
    fn last_fatal(&self) -> Option<String> {
        self.last_fatal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// Forward the recovery mongod's log to this container's stdout, line by
/// line, noting what the verdict needs. mongod blocks on a full pipe, so this
/// runs for the whole life of the child.
async fn forward_log(stdout: ChildStdout, observed: Arc<Observed>) {
    let mut lines = BufReader::new(stdout).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if mongod_log_id(&line) == Some(NO_OPLOG_LOG_ID) {
            observed.saw_no_oplog.store(true, Ordering::SeqCst);
        }
        if is_fatal_line(&line) {
            *observed
                .last_fatal
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(line.clone());
        }
        println!("{line}");
    }
}

/// A credential-less loopback client: `ping` needs no authentication, and
/// readiness must not depend on the wrapper's password being the one mongod
/// enforces (the recovery boot has to run through credential drift too).
fn loopback_client(port: u16) -> Client {
    let options = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host: "127.0.0.1".to_string(),
            port: Some(port),
        }])
        .direct_connection(true)
        .app_name("mongo-wrapper-recovery".to_string())
        .server_selection_timeout(Duration::from_millis(800))
        .connect_timeout(Duration::from_millis(800))
        .build();
    Client::with_options(options).expect("static client options are valid")
}

async fn answers_ping(client: &Client) -> bool {
    tokio::time::timeout(
        Duration::from_secs(2),
        client.database("admin").run_command(doc! { "ping": 1 }),
    )
    .await
    .map(|outcome| outcome.is_ok())
    .unwrap_or(false)
}

/// Run the recovery boot to completion: spawn the recovery mongod, wait until
/// it accepts connections (replication recovery runs before the listener
/// opens, so "up" means "replayed"), stop it with SIGTERM and wait for its
/// shutdown checkpoint. See the module doc for the verdicts.
pub async fn replay_oplog_as_standalone(config: &Config, args: &[String]) -> Result<Replay> {
    let flags = recovery_flags(config);
    info!(
        ?flags,
        "replica set volume booting standalone: replaying the oplog first (recovery mongod on the \
         loopback; the real standalone mongod starts once it has checkpointed)"
    );
    let mut child = process_manager::mongod_command(&flags, args)
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to spawn the recovery mongod")?;
    let stdout = child
        .stdout
        .take()
        .context("the recovery mongod has no stdout pipe")?;
    let observed = Arc::new(Observed::default());
    let forward = tokio::spawn(forward_log(stdout, observed.clone()));

    let client = loopback_client(config.mongo_port);
    let started = Instant::now();
    let mut last_progress = started;
    loop {
        if let Some(status) = child.try_wait().context("waiting on the recovery mongod")? {
            // Let the pipe drain so the verdict sees the last lines.
            let _ = tokio::time::timeout(Duration::from_secs(5), forward).await;
            return early_exit_verdict(
                observed.saw_no_oplog.load(Ordering::SeqCst),
                status.code(),
                observed.last_fatal().as_deref(),
            );
        }
        if answers_ping(&client).await {
            break;
        }
        if last_progress.elapsed() >= PROGRESS_EVERY {
            info!(
                elapsed_secs = started.elapsed().as_secs(),
                "recovery mongod still replaying the oplog"
            );
            last_progress = Instant::now();
        }
        tokio::time::sleep(POLL).await;
    }
    client.shutdown().await;
    info!(
        elapsed_secs = started.elapsed().as_secs(),
        "recovery mongod is up, the oplog is replayed; stopping it cleanly so the checkpoint is taken"
    );
    stop_cleanly(&mut child).await?;
    let _ = tokio::time::timeout(Duration::from_secs(5), forward).await;
    info!(
        elapsed_secs = started.elapsed().as_secs(),
        "recovery boot finished: the replayed state is checkpointed"
    );
    Ok(Replay::Replayed)
}

/// SIGTERM the recovery mongod and wait for its clean exit — the shutdown
/// checkpoint is the whole point, so it is never killed, only waited on.
async fn stop_cleanly(child: &mut Child) -> Result<()> {
    let pid = child
        .id()
        .map(|id| Pid::from_raw(id as i32))
        .context("the recovery mongod has no pid")?;
    signal::kill(pid, Signal::SIGTERM).context("signaling the recovery mongod")?;
    let started = Instant::now();
    let mut last_progress = started;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .context("waiting for the recovery mongod to exit")?
        {
            break status;
        }
        if started.elapsed() >= SHUTDOWN_LIMIT {
            bail!(
                "the recovery mongod did not finish its shutdown checkpoint within {}s",
                SHUTDOWN_LIMIT.as_secs()
            );
        }
        if last_progress.elapsed() >= PROGRESS_EVERY {
            info!(
                elapsed_secs = started.elapsed().as_secs(),
                "recovery mongod still writing its shutdown checkpoint"
            );
            last_progress = Instant::now();
        }
        tokio::time::sleep(POLL).await;
    };
    if !status.success() {
        bail!(
            "the recovery mongod exited with code {:?} during its shutdown; the checkpoint may not \
             have been taken",
            status.code()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(data_dir: &str) -> Config {
        Config {
            mongo_root_username: "mongo".into(),
            mongo_root_password: "pw".into(),
            mongo_port: 27017,
            rs_enabled_flag: false,
            rs_seeds: None,
            rs_name: "rs0".into(),
            rs_key: None,
            keyfile_path: "/run/mongo-ha/keyfile".into(),
            health_port: 8080,
            private_domain: "mongo-1".into(),
            data_dir: data_dir.into(),
            peer_query_timeout_ms: 2000,
            bootstrap_dwell_seconds: 15,
            demote_timeout_ms: 20_000,
            peer_gone_dwell_seconds: 1800,
        }
    }

    #[test]
    fn the_replay_runs_only_on_a_dataset_that_ran_as_a_member() {
        let member = AuthPin {
            password: "pw".into(),
            keyfile: Some("K==".into()),
        };
        let standalone = AuthPin {
            password: "pw".into(),
            keyfile: None,
        };
        // The revert: an HA volume booting without RS_SEEDS.
        assert!(replay_needed(true, Some(&member)));
        // A fresh volume has nothing to replay whatever the pin says.
        assert!(!replay_needed(false, Some(&member)));
        assert!(!replay_needed(false, None));
        // A volume that only ever ran standalone has no oplog: the recovery
        // boot would be fatal there, so it must not run.
        assert!(!replay_needed(true, Some(&standalone)));
        // No pin at all (upstream-image volume, torn pin): today's boot.
        assert!(!replay_needed(true, None));
    }

    #[test]
    fn recovery_flags_bind_the_loopback_and_set_both_parameters() {
        let flags = recovery_flags(&config("/data/db"));
        let joined = flags.join(" ");
        assert!(joined.contains("--bind_ip 127.0.0.1"));
        assert!(joined.contains("--port 27017"));
        assert!(joined.contains("--setParameter recoverFromOplogAsStandalone=true"));
        assert!(joined.contains("--setParameter takeUnstableCheckpointOnShutdown=true"));
        assert!(
            !joined.contains("--replSet"),
            "the recovery boot is a standalone"
        );
        assert!(!joined.contains("--bind_ip_all") && !joined.contains("--ipv6"));
        assert!(
            !joined.contains("--dbpath"),
            "default dbpath is left implicit"
        );
        let custom = recovery_flags(&config("/mnt/data")).join(" ");
        assert!(custom.contains("--dbpath /mnt/data"));
    }

    #[test]
    fn mongod_log_ids_are_read_from_json_lines() {
        let drop = r#"{"t":{"$date":"2026-09-07T20:55:26.934+00:00"},"s":"I",  "c":"STORAGE",  "id":22251,   "ctx":"initandlisten","msg":"Dropping unknown ident","attr":{"ident":"collection-13-2942877795230192485"}}"#;
        assert_eq!(mongod_log_id(drop), Some(22251));
        assert!(!is_fatal_line(drop));
        let fatal = r#"{"t":{"$date":"2026-09-08T00:00:00.000+00:00"},"s":"F",  "c":"REPL",     "id":31364,   "ctx":"initandlisten","msg":"Recovery not possible, no oplog found","attr":{"error":{"code":26,"codeName":"NamespaceNotFound"}}}"#;
        assert_eq!(mongod_log_id(fatal), Some(NO_OPLOG_LOG_ID));
        assert!(is_fatal_line(fatal));
        // The wrapper's own tracing lines and plain text are not mongod's.
        assert_eq!(
            mongod_log_id(r#"{"timestamp":"...","level":"INFO","fields":{"message":"x"}}"#),
            None
        );
        assert_eq!(mongod_log_id("MongoDB init process complete"), None);
        assert_eq!(mongod_log_id(r#"{"id":"not-a-number"}"#), None);
    }

    #[test]
    fn an_early_exit_is_a_verdict_only_for_a_missing_oplog() {
        assert_eq!(
            early_exit_verdict(true, Some(14), Some("...31364...")).unwrap(),
            Replay::NoOplog
        );
        let err = early_exit_verdict(false, Some(14), Some("fatal line")).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("code 14") && text.contains("fatal line"));
        let err = early_exit_verdict(false, None, None).unwrap_err();
        assert!(format!("{err:#}").contains("killed by a signal"));
    }

    #[test]
    fn the_failure_guidance_names_the_variables_and_the_fix() {
        let text = recovery_failed_guidance(Some(14), None);
        for needle in [
            "recoverFromOplogAsStandalone",
            "RS_ENABLED=true",
            "RS_SEEDS",
            "RS_KEY",
            "revert again",
            "data directory is unchanged",
            "restore from a backup",
        ] {
            assert!(text.contains(needle), "missing {needle:?}");
        }
    }
}
