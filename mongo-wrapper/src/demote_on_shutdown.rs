//! Hand the primary role off BEFORE mongod is signaled to stop, so a
//! *planned* shutdown (redeploy, restart, scale) pays a step-down with
//! catch-up instead of the detection-timeout failover the set would run once
//! it notices the primary vanished (`electionTimeoutMillis`, 10s by default,
//! plus an election).
//!
//! mongod ships the exact primitive: `replSetStepDown` waits up to
//! `secondaryCatchUpPeriodSecs` for a secondary to catch up, then steps down
//! — the same handoff redis-ha does through Sentinel and mysql-ha through
//! `group_replication_set_as_primary`.
//!
//! Runs from `process_manager::supervise`'s signal arms, strictly BEFORE
//! mongod is signaled — the server must still be up to drive the handoff. HA
//! mode only; a standalone node has nobody to hand off to. Any refusal or
//! timeout is logged at warn and shutdown proceeds unchanged — a failed
//! demote must never block or slow the shutdown it was trying to smooth.

use crate::mongo::Mongo;
use std::time::Duration;
use tracing::{info, warn};

/// How long the stepping-down primary waits for a secondary to catch up.
const CATCHUP_SECS: i64 = 10;
/// How long the demoted node refuses to seek election — long enough to
/// cover the shutdown; irrelevant once the process is gone.
const STEPDOWN_SECS: i64 = 60;

pub struct DemoteCtx {
    pub mongo: Mongo,
    /// Overall bound on the whole demote attempt, milliseconds.
    pub deadline_ms: u64,
}

/// Demote this node if it is the current primary. Never errors and never
/// blocks past the deadline: shutdown always proceeds.
pub async fn demote_if_primary(ctx: &DemoteCtx) {
    let deadline = Duration::from_millis(ctx.deadline_ms);
    let outcome = tokio::time::timeout(deadline, async {
        let hello = ctx.mongo.hello().await?;
        if !hello.is_writable_primary {
            return anyhow::Ok(false);
        }
        info!("stepping down before shutdown");
        ctx.mongo.step_down(STEPDOWN_SECS, CATCHUP_SECS).await?;
        anyhow::Ok(true)
    })
    .await;

    match outcome {
        Ok(Ok(true)) => info!("demoted before shutdown: primary stepped down"),
        Ok(Ok(false)) => {}
        Ok(Err(e)) => {
            warn!(error = %format!("{e:#}"), "demote-on-shutdown failed; proceeding with shutdown");
        }
        Err(_) => {
            warn!(
                deadline_ms = ctx.deadline_ms,
                "demote-on-shutdown timed out; proceeding with shutdown"
            );
        }
    }
}
