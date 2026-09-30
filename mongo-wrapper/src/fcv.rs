//! Feature-compatibility-version completion: the image finishes the version
//! move a deploy started.
//!
//! MongoDB does not complete an upgrade on its own. After the binary moves
//! from 8.2 to 8.3 the data files stay at `featureCompatibilityVersion` 8.2
//! until somebody runs `setFeatureCompatibilityVersion`. That half-upgraded
//! state works — until the NEXT move: mongod N starts only on FCV N or N-1,
//! so a service left at 8.2 crashes on boot the day its tag resolves to 8.4.
//! MySQL converts its data directory on first start; this module gives the
//! Mongo image the same property: once mongod answers, the wrapper raises FCV
//! to the running release and reads it back, on every boot, whatever moved
//! the binary (the platform's vuln lane, a customer redeploy, a tag float).
//!
//! Standalone: raised as soon as mongod is up. Replica set: only on the
//! primary, and only once every member is healthy and reports the same binary
//! series — a raised FCV evicts a member still on the old binary, which is
//! exactly the state a rolling upgrade passes through. Every other state waits
//! and re-checks. Nothing here lowers FCV, and nothing here stops the boot:
//! mongod is up and the data is intact, a lagging FCV is what the fleet has
//! today, so a failed step is logged (and sent as a component error) and
//! retried on the next round, never fatal.

use crate::config::Config;
use crate::mongo::{Fcv, Mongo, RsStatus};
use common::{Telemetry, TelemetryEvent};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// How often the FCV is re-checked while something blocks the raise (a
/// transition in flight, a member still on the old binary, this node not
/// being the primary).
const WAIT_INTERVAL: Duration = Duration::from_secs(30);
/// The `FCV_RECHECK_SECONDS` default: how often an up-to-date node re-reads
/// FCV. A role change (this node elected after the old primary died with the
/// FCV still lagging) or a rolling upgrade finishing on the last member is
/// what this catches; cheap, one admin command.
const DEFAULT_RECHECK: Duration = Duration::from_secs(600);

/// What this node's mongod is, for the raise decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Standalone,
    Primary,
    /// A secondary, an arbiter, a member without a config yet: anything that
    /// is not the primary of a set.
    NotPrimary,
}

/// One OTHER member of the set, as the primary sees it: whether the set
/// reports it healthy and which binary series it answered `buildInfo` with
/// (None: unreachable or unparsable — never assumed current).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberSeries {
    pub host: String,
    pub healthy: bool,
    pub series: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// FCV already names the running series.
    UpToDate,
    /// Run `setFeatureCompatibilityVersion` to this series.
    Raise { to: String },
    /// Not now: re-check later, with the reason (logged once per distinct
    /// reason, not once per poll).
    Wait { reason: String },
    /// Never: the values make no sense together (an FCV ABOVE the running
    /// binary, an unparsable series). Logged as an error; nothing is changed.
    Refuse { reason: String },
}

/// `"8.3.1"` / `"8.3"` → `(8, 3)`; None for anything else.
pub fn parse_series(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    Some((major, minor))
}

/// `"8.3.1"` → `"8.3"`: the `major.minor` series a version belongs to, which
/// is also the FCV value that names it.
pub fn series_of(version: &str) -> Option<String> {
    parse_series(version).map(|(major, minor)| format!("{major}.{minor}"))
}

/// The pure decision. `running` is the series mongod reported in `buildInfo`;
/// `fcv` what `getParameter` said; `members` the OTHER members of the set as
/// the primary sees them (empty for a standalone; ignored unless `role` is
/// `Primary`).
pub fn decide(running: &str, fcv: &Fcv, role: Role, members: &[MemberSeries]) -> Decision {
    let Some(running_series) = parse_series(running) else {
        return Decision::Refuse {
            reason: format!("running version {running:?} has no major.minor"),
        };
    };
    let Some(current) = parse_series(&fcv.version) else {
        return Decision::Refuse {
            reason: format!(
                "featureCompatibilityVersion {:?} has no major.minor",
                fcv.version
            ),
        };
    };
    if let Some(target) = &fcv.target {
        return Decision::Wait {
            reason: format!(
                "an FCV transition to {target} is in flight (currently {})",
                fcv.version
            ),
        };
    }
    if current == running_series {
        return Decision::UpToDate;
    }
    if current > running_series {
        return Decision::Refuse {
            reason: format!(
                "featureCompatibilityVersion {} is above the running series {}.{}",
                fcv.version, running_series.0, running_series.1
            ),
        };
    }
    let to = format!("{}.{}", running_series.0, running_series.1);
    match role {
        Role::Standalone => Decision::Raise { to },
        Role::NotPrimary => Decision::Wait {
            reason: format!(
                "FCV {} lags the running {to}; only the primary raises it",
                fcv.version
            ),
        },
        Role::Primary => {
            if let Some(m) = members.iter().find(|m| !m.healthy) {
                return Decision::Wait {
                    reason: format!("member {} is not healthy; a raise would strand it", m.host),
                };
            }
            if let Some(m) = members.iter().find(|m| m.series.is_none()) {
                return Decision::Wait {
                    reason: format!("member {} did not report its binary version", m.host),
                };
            }
            if let Some(m) = members.iter().find(|m| {
                m.series
                    .as_deref()
                    .and_then(parse_series)
                    .is_none_or(|s| s < running_series)
            }) {
                return Decision::Wait {
                    reason: format!(
                        "member {} runs {} while this node runs {to}; a rolling upgrade is in progress",
                        m.host,
                        m.series.as_deref().unwrap_or("?")
                    ),
                };
            }
            Decision::Raise { to }
        }
    }
}

/// The re-check interval for an up-to-date node: `FCV_RECHECK_SECONDS`, or
/// the default. Tests shorten it.
fn recheck_interval() -> Duration {
    std::env::var("FCV_RECHECK_SECONDS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_RECHECK)
}

/// Runs for the life of the container: waits for the final mongod, then keeps
/// FCV at the running series (see the module doc). Spawned in both modes.
pub async fn reconcile(config: Arc<Config>, mongo: Mongo, telemetry: Arc<Telemetry>) {
    crate::rs::wait_for_final_mongod(&mongo, &config).await;
    let mut last_reason = String::new();
    let mut last_error = String::new();
    loop {
        let sleep = match round(&config, &mongo).await {
            Ok(Decision::UpToDate) => {
                last_reason.clear();
                last_error.clear();
                recheck_interval()
            }
            Ok(Decision::Raise { to }) => {
                info!(to = %to, "raising featureCompatibilityVersion to the running release");
                match raise(&mongo, &to).await {
                    Ok(()) => {
                        info!(fcv = %to, "featureCompatibilityVersion raised and verified");
                        last_reason.clear();
                        last_error.clear();
                        recheck_interval()
                    }
                    Err(e) => {
                        report(&telemetry, &mut last_error, "raise", &e);
                        WAIT_INTERVAL
                    }
                }
            }
            Ok(Decision::Wait { reason }) => {
                if last_reason != reason {
                    info!(%reason, "featureCompatibilityVersion not raised yet");
                    last_reason = reason;
                }
                WAIT_INTERVAL
            }
            Ok(Decision::Refuse { reason }) => {
                let e = anyhow::anyhow!("{reason}");
                report(&telemetry, &mut last_error, "decide", &e);
                recheck_interval()
            }
            Err(e) => {
                report(&telemetry, &mut last_error, "read", &e);
                WAIT_INTERVAL
            }
        };
        tokio::time::sleep(sleep).await;
    }
}

/// One read of the facts and the decision they imply.
async fn round(config: &Config, mongo: &Mongo) -> anyhow::Result<Decision> {
    let running = mongo.build_info_series().await?;
    let fcv = mongo.fcv().await?;
    if !config.rs_enabled() {
        return Ok(decide(&running, &fcv, Role::Standalone, &[]));
    }
    let hello = mongo.hello().await?;
    if !hello.is_writable_primary {
        return Ok(decide(&running, &fcv, Role::NotPrimary, &[]));
    }
    let members = match mongo.rs_status().await? {
        RsStatus::Active { members, .. } => members,
        _ => {
            return Ok(Decision::Wait {
                reason: "this node reports primary but holds no replica set status yet".to_string(),
            })
        }
    };
    let mut peers = Vec::with_capacity(members.len());
    for m in members.into_iter().filter(|m| !m.is_self) {
        // One direct connection per peer, with this node's own credentials
        // (every member of a keyfile set shares the root account). A peer
        // that does not answer is "unknown", never "current".
        let series = if m.healthy {
            let peer = mongo.peer(&m.host).await;
            let series = peer.build_info_series().await.ok();
            peer.shutdown().await;
            series
        } else {
            None
        };
        peers.push(MemberSeries {
            host: m.host,
            healthy: m.healthy,
            series,
        });
    }
    Ok(decide(&running, &fcv, Role::Primary, &peers))
}

/// `setFeatureCompatibilityVersion` then read back: only a read that names
/// `to` counts. A command that timed out may still have completed; the read
/// decides, and the next round retries anything short of the target.
async fn raise(mongo: &Mongo, to: &str) -> anyhow::Result<()> {
    if let Err(e) = mongo.set_fcv(to).await {
        warn!(error = %format!("{e:#}"), "setFeatureCompatibilityVersion did not return cleanly; reading back");
    }
    let after = mongo.fcv().await?;
    anyhow::ensure!(
        after.version == to && after.target.is_none(),
        "featureCompatibilityVersion reads {} (target {:?}) after asking for {to}",
        after.version,
        after.target
    );
    Ok(())
}

fn report(telemetry: &Telemetry, last: &mut String, context: &str, e: &anyhow::Error) {
    let error = format!("{e:#}");
    if *last == error {
        return;
    }
    *last = error.clone();
    error!(error = %error, context, "featureCompatibilityVersion completion failed; will retry");
    telemetry.send(TelemetryEvent::ComponentError {
        component: "fcv".to_string(),
        error,
        context: format!("fcv-{context}"),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fcv(version: &str) -> Fcv {
        Fcv {
            version: version.to_string(),
            target: None,
        }
    }

    fn member(host: &str, healthy: bool, series: Option<&str>) -> MemberSeries {
        MemberSeries {
            host: host.to_string(),
            healthy,
            series: series.map(str::to_string),
        }
    }

    #[test]
    fn series_parsing() {
        assert_eq!(parse_series("8.3.1"), Some((8, 3)));
        assert_eq!(parse_series("8.3"), Some((8, 3)));
        assert_eq!(parse_series("8.3.1-rc0"), Some((8, 3)));
        assert_eq!(parse_series("8"), None);
        assert_eq!(parse_series("x.y"), None);
        assert_eq!(series_of("7.0.41"), Some("7.0".to_string()));
    }

    #[test]
    fn matching_fcv_is_up_to_date_in_every_role() {
        for role in [Role::Standalone, Role::Primary, Role::NotPrimary] {
            assert_eq!(decide("8.3.1", &fcv("8.3"), role, &[]), Decision::UpToDate);
        }
    }

    #[test]
    fn standalone_raises_right_away() {
        assert_eq!(
            decide("8.3.1", &fcv("8.2"), Role::Standalone, &[]),
            Decision::Raise { to: "8.3".into() }
        );
        // Across a major (7.0 → 8.0) as well: the LTS step mongod accepts.
        assert_eq!(
            decide("8.0.30", &fcv("7.0"), Role::Standalone, &[]),
            Decision::Raise { to: "8.0".into() }
        );
    }

    #[test]
    fn a_transition_in_flight_waits() {
        let in_flight = Fcv {
            version: "8.2".into(),
            target: Some("8.3".into()),
        };
        assert!(matches!(
            decide("8.3.1", &in_flight, Role::Standalone, &[]),
            Decision::Wait { .. }
        ));
    }

    #[test]
    fn fcv_above_the_binary_is_refused_never_lowered() {
        assert!(matches!(
            decide("8.2.12", &fcv("8.3"), Role::Standalone, &[]),
            Decision::Refuse { .. }
        ));
        assert!(matches!(
            decide("garbage", &fcv("8.3"), Role::Standalone, &[]),
            Decision::Refuse { .. }
        ));
    }

    #[test]
    fn only_the_primary_raises_in_a_set() {
        assert!(matches!(
            decide("8.3.1", &fcv("8.2"), Role::NotPrimary, &[]),
            Decision::Wait { .. }
        ));
        let peers = [
            member("mongo-2:27017", true, Some("8.3")),
            member("mongo-3:27017", true, Some("8.3")),
        ];
        assert_eq!(
            decide("8.3.1", &fcv("8.2"), Role::Primary, &peers),
            Decision::Raise { to: "8.3".into() }
        );
    }

    #[test]
    fn primary_waits_while_any_member_lags_or_is_unknown() {
        let lagging = [
            member("mongo-2:27017", true, Some("8.3")),
            member("mongo-3:27017", true, Some("8.2")),
        ];
        let Decision::Wait { reason } = decide("8.3.1", &fcv("8.2"), Role::Primary, &lagging)
        else {
            panic!("expected a wait while mongo-3 runs 8.2");
        };
        assert!(reason.contains("mongo-3:27017"), "{reason}");

        let unknown = [member("mongo-2:27017", true, None)];
        assert!(matches!(
            decide("8.3.1", &fcv("8.2"), Role::Primary, &unknown),
            Decision::Wait { .. }
        ));

        let unhealthy = [member("mongo-2:27017", false, Some("8.3"))];
        assert!(matches!(
            decide("8.3.1", &fcv("8.2"), Role::Primary, &unhealthy),
            Decision::Wait { .. }
        ));
    }

    #[test]
    fn a_member_ahead_of_the_primary_does_not_block() {
        // Mid rolling upgrade the primary is usually the LAST binary to move;
        // a member already past this node's series is no reason to wait —
        // the raise targets this node's series, which that member accepts.
        let ahead = [member("mongo-2:27017", true, Some("8.4"))];
        assert_eq!(
            decide("8.3.1", &fcv("8.2"), Role::Primary, &ahead),
            Decision::Raise { to: "8.3".into() }
        );
    }
}
