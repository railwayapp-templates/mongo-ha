//! Process supervision for the mongod subprocess.
//!
//! Adapted from mysql-ha's single-child supervisor: spawn the upstream
//! entrypoint, forward signals, and exit the container with the child's own
//! exit code if it dies, letting Railway's restart policy handle recovery.

use anyhow::{Context, Result};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::sync::atomic::{AtomicI32, Ordering};
use tokio::process::{Child, Command};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

/// Exit code of a fail-stop: the wrapper found itself configured in a way it
/// must not run with (a joiner whose root credentials the live set refuses)
/// and stops, with the fix in its log. Non-zero so the deployment reads as
/// failed — never as a clean exit — and the restart policy retries the boot,
/// which succeeds once the variables are restored. 78 is EX_CONFIG.
pub const FAIL_STOP_EXIT_CODE: i32 = 78;

static FAIL_STOP_REQUESTED: AtomicI32 = AtomicI32::new(0);

/// Ask the supervisor to shut mongod down gracefully and exit with
/// `FAIL_STOP_EXIT_CODE`. For tasks that run beside `supervise`: it delivers
/// SIGTERM to this process, which the signal branch below turns into the
/// ordinary graceful shutdown — exiting with the fail-stop code instead of 0.
pub fn request_fail_stop() {
    FAIL_STOP_REQUESTED.store(FAIL_STOP_EXIT_CODE, Ordering::SeqCst);
    if let Err(e) = signal::kill(Pid::this(), Signal::SIGTERM) {
        error!(error = %e, "could not signal the supervisor for a fail-stop; exiting directly");
        std::process::exit(FAIL_STOP_EXIT_CODE);
    }
}

/// What a signal-driven shutdown exits with: 0 for a plain stop, the
/// fail-stop code once one was requested.
fn shutdown_exit_code() -> i32 {
    FAIL_STOP_REQUESTED.load(Ordering::SeqCst)
}

/// Spawn the upstream entrypoint with the wrapper-owned flags first and any
/// CLI args this process was itself invoked with appended — mirrors
/// `docker-entrypoint.sh mongod [flags...] [args...]`.
///
/// The entrypoint owns first-boot initialization (the root user, from
/// MONGO_INITDB_ROOT_USERNAME/PASSWORD in the inherited environment) and
/// runs it against a temporary server it starts WITHOUT `--replSet`,
/// `--keyFile` and `--auth` — which is why the orchestrator waits for the
/// final server (see rs::wait_for_final_mongod) before touching anything.
pub async fn spawn_mongod(flags: &[String], args: &[String]) -> Result<Child> {
    info!(?flags, ?args, "starting docker-entrypoint.sh mongod");

    Command::new("docker-entrypoint.sh")
        .arg("mongod")
        .args(flags)
        .args(args)
        .kill_on_drop(false)
        .spawn()
        .context("failed to spawn docker-entrypoint.sh mongod")
}

/// Supervise the mongod child: forward SIGTERM/SIGINT and wait for a graceful
/// exit, or exit the container immediately (with the child's own code) if it
/// dies on its own.
///
/// `demote` — present in HA mode only: hand the primary role off through the
/// set BEFORE mongod is signaled, so a planned shutdown is a step-down with
/// catch-up rather than a detection-timeout failover (see
/// demote_on_shutdown.rs). A failure there never blocks the shutdown.
pub async fn supervise(
    mut child: Child,
    demote: Option<crate::demote_on_shutdown::DemoteCtx>,
) -> Result<()> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let pid = child.id().map(|id| Pid::from_raw(id as i32));

    // Every arm below ends the process — the "loop" runs at most once.
    #[allow(clippy::never_loop)]
    loop {
        tokio::select! {
            status = child.wait() => {
                let code = match status {
                    Ok(s) => {
                        error!(code = s.code(), "mongod exited unexpectedly");
                        s.code().unwrap_or(1)
                    }
                    Err(e) => {
                        error!(error = %format!("{e:#}"), "mongod wait error");
                        1
                    }
                };
                // An unasked exit must never look like success: with an
                // ON_FAILURE restart policy, propagating mongod's clean 0
                // here leaves the container "exited (0)" and the database
                // down until a human redeploys. Every deliberate stop goes
                // through the signal branches below, which are the only
                // paths allowed to exit 0 (or the fail-stop code, when a task
                // asked for one — see request_fail_stop).
                std::process::exit(if code == 0 { 1 } else { code });
            }

            _ = sigterm.recv() => {
                if shutdown_exit_code() != 0 {
                    warn!(code = shutdown_exit_code(), "fail-stop requested; shutting mongod down and exiting non-zero");
                } else {
                    info!("received SIGTERM, shutting down");
                }
                if let Some(ctx) = &demote {
                    crate::demote_on_shutdown::demote_if_primary(ctx).await;
                }
                graceful_shutdown(pid, &mut child).await;
                std::process::exit(shutdown_exit_code());
            }

            _ = sigint.recv() => {
                info!("received SIGINT, shutting down");
                if let Some(ctx) = &demote {
                    crate::demote_on_shutdown::demote_if_primary(ctx).await;
                }
                graceful_shutdown(pid, &mut child).await;
                std::process::exit(shutdown_exit_code());
            }
        }
    }
}

async fn graceful_shutdown(pid: Option<Pid>, child: &mut Child) {
    if let Some(pid) = pid {
        info!("sending SIGTERM to mongod");
        let _ = signal::kill(pid, Signal::SIGTERM);
        tokio::select! {
            _ = child.wait() => {}
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                warn!("mongod did not exit in time, killing");
                let _ = child.kill().await;
            }
        }
    }
}
