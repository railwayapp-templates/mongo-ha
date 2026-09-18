//! Oplog-window / stuck-member monitoring.
//!
//! Observation and reporting ONLY — no self-heal, no auto-resync, no
//! remediation of any kind. That boundary is a v1 product decision (see the
//! README's Status section) and this module must not cross it.
//!
//! This is the single most field-validated MongoDB replica-set HA failure
//! mode: a member whose replication has fallen far enough behind the primary
//! that the entry it still needs has already been overwritten in the
//! primary's oplog cannot catch up incrementally at all — it needs a full
//! resync (mongod's own log line for this is "Too stale to catch up", which
//! backboard's log classifier already greps for reactively). MongoDB Atlas
//! ships a dedicated alert for the leading indicator (oplog window shrinking)
//! rather than waiting for that terminal state. Until this module, mongo-ha
//! had neither: no oplog sizing, no lag sampling, nothing emitted for a
//! member stuck in RECOVERING/STARTUP2. See the research notes this was
//! built from under `.claude/audit/quarter/research/mongo-ha/`, especially
//! `04-atlas-oplog-alert-resolution.md` and `05-community-forum-stale-resync.md`
//! (an operator who lost 15+ hours to exactly this, undetected).
//!
//! Runs on the PRIMARY only (see `rs::member_duties`), reusing the same
//! `replSetGetStatus` view `prune_round` already reads and the primary's own
//! `local.oplog.rs` — the primary's oplog is the set's constraining resource,
//! since every member is bounded by how far behind the entries the primary
//! has already overwritten. No new timer, no new cross-node calls: the
//! primary already sees every member's reported state and last-applied
//! optime through the same heartbeat-fed view `prune_round` uses for
//! membership pruning.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// mongod's own `stateStr` for a member that answered `hello`'s temporary
/// server on first boot and has not started initial sync — the two "still
/// catching up" states this module watches for a stuck dwell. Every other
/// member state either serves traffic already (PRIMARY, SECONDARY) or is
/// covered by other telemetry: DOWN/UNKNOWN by health/pruning, ROLLBACK is
/// brief-and-self-resolving, REMOVED is membership-prune's own event.
pub const RECOVERING: &str = "RECOVERING";
pub const STARTUP2: &str = "STARTUP2";

/// How long a member may continuously report RECOVERING/STARTUP2 before it
/// counts as *stuck* rather than an ordinary transition. mysql-ha's own
/// stuck-member watch (`STUCK_MEMBER_DWELL_SECONDS`) uses 900s (15 minutes)
/// to tell a real stall apart from routine catch-up before its self-heal
/// arms; this module only reports (no self-heal to arm), so the same bar is
/// reused as-is rather than inventing a fresh number — it is comfortably
/// above every RECOVERING/STARTUP2 duration mongo-ha's own e2e suite observes
/// during ordinary scale-up (single-digit seconds, empty test datasets), and
/// it leaves an operator hours of runway before it repeats the 15+ hour
/// stale-secondary disaster the community forum reports (05).
pub const STUCK_STATE_DWELL: Duration = Duration::from_secs(900);

/// Below this much wall-clock history, the primary's oplog no longer buys
/// the set a comfortable margin against a routine disruption on a secondary.
/// Atlas ships a dedicated alert for this exact quantity (04) with no fixed
/// universal number published — it is operator-tunable there too. One hour
/// is chosen here because every *planned* disruption this wrapper itself
/// introduces (a demote-on-shutdown handoff, a supervised mongod respawn,
/// the initiate/join dwells — see rs.rs / health_server.rs) completes in
/// well under a minute, so an hour of headroom comfortably outlives any of
/// the wrapper's own routine operations while still catching a shrinking
/// oplog long before it approaches zero.
pub const OPLOG_WINDOW_FLOOR: Duration = Duration::from_secs(3600);

/// The share of the primary's current oplog window a member's lag may
/// consume before this module reports it as *about to* fall off, rather
/// than waiting for it to already have (lag >= 100% of the window — at that
/// point mongod itself is already refusing incremental sync; see the
/// module doc's "Too stale to catch up" reference). Firing at three-quarters
/// gives an operator real lead time instead of a same-instant "too late"
/// alert; this is the condition the task that built this module called out
/// as the one that matters most.
pub const LAG_VS_OPLOG_WINDOW_WARN_RATIO: f64 = 0.75;

/// How long each member has continuously reported its CURRENT `stateStr` —
/// reset the moment the reported state changes. `replSetGetStatus` reports
/// only the state, never how long a member has held it, so "RECOVERING for
/// 20 minutes" has to be told apart from a fresh 5-second transition by
/// tracking it here across polls (the same shape as `rs::GoneTracker`, one
/// clock per host).
pub struct MemberStateTracker {
    since: HashMap<String, (String, Instant)>,
}

impl Default for MemberStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl MemberStateTracker {
    pub fn new() -> Self {
        Self {
            since: HashMap::new(),
        }
    }

    /// Record this poll's observed state for `host`, returning how long it
    /// has continuously held that state, this observation included. A state
    /// different from the last one recorded resets the clock to zero.
    pub fn observe(&mut self, host: &str, state: &str, now: Instant) -> Duration {
        match self.since.get(host) {
            Some((prev, since)) if prev == state => now.duration_since(*since),
            _ => {
                self.since
                    .insert(host.to_string(), (state.to_string(), now));
                Duration::ZERO
            }
        }
    }

    /// Drop any tracked host not in the current membership view, so a member
    /// pruned and later re-added under the same name starts its dwell clock
    /// fresh instead of inheriting a stale one.
    pub fn retain_known(&mut self, hosts: &[String]) {
        self.since.retain(|h, _| hosts.contains(h));
    }
}

/// One member's row, as read off the primary's own `replSetGetStatus`, with
/// this poll's dwell already resolved by `MemberStateTracker`. The impure
/// boundary (rs.rs) builds these from `mongo::RsMember` + the tracker; this
/// struct is deliberately free of bson/mongodb types so tests can build it
/// directly from plain values — matching the task's request for synthetic
/// `replSetGetStatus` shapes without needing a live server.
#[derive(Debug, Clone, PartialEq)]
pub struct MemberObservation {
    pub host: String,
    pub state_str: String,
    /// Last applied optime, seconds since epoch — `None` when this member
    /// has not applied anything yet (freshly added, still in initial sync).
    pub optime_secs: Option<u32>,
    pub is_self: bool,
    pub dwell: Duration,
}

/// A threshold crossing worth telling an operator about. Each variant knows
/// its own dedupe key (`key`) — an incident identity used to emit once per
/// crossing rather than once per poll — and how to render itself into the
/// wrapper's existing `ComponentError` telemetry shape (see rs.rs's
/// `replication_health_round`), the same shape every other mongo-specific
/// event already reports through (membership prune, credential drift,
/// initiate failure): `common::TelemetryEvent` stays engine-neutral by
/// design, so this module does not add new wire variants there.
#[derive(Debug, Clone, PartialEq)]
pub enum ReplicationSignal {
    /// Stuck in RECOVERING/STARTUP2 well past a normal transition.
    StuckInState {
        host: String,
        state: String,
        stuck_for: Duration,
    },
    /// Lag has eaten most (or all) of the primary's current oplog window —
    /// the "about to fall off / has fallen off" condition.
    FallingOffOplog {
        host: String,
        lag: Duration,
        oplog_window: Duration,
    },
    /// The primary's own oplog window has shrunk below the floor.
    OplogWindowLow { oplog_window: Duration },
}

impl ReplicationSignal {
    /// Identity for the "already alerting on this" set `replication_health_round`
    /// keeps: distinct per (signal kind, member) so one member's stuck state
    /// does not suppress another's, and a single instance for the
    /// set-wide oplog-window-low signal (there is only one primary oplog).
    pub fn dedupe_key(&self) -> String {
        match self {
            Self::StuckInState { host, .. } => format!("stuck:{host}"),
            Self::FallingOffOplog { host, .. } => format!("falling-off:{host}"),
            Self::OplogWindowLow { .. } => "oplog-window-low".to_string(),
        }
    }

    /// The telemetry `context` — what rs.rs's other `ComponentError` sends
    /// use to distinguish their narratives under one grouped event type.
    pub fn context(&self) -> &'static str {
        match self {
            Self::StuckInState { .. } => "member-stuck-in-state",
            Self::FallingOffOplog { .. } => "replication-lag-vs-oplog-window",
            Self::OplogWindowLow { .. } => "oplog-window-low",
        }
    }

    /// One-line human summary, sent as the telemetry `error`.
    pub fn message(&self) -> String {
        match self {
            Self::StuckInState {
                host,
                state,
                stuck_for,
            } => format!(
                "{host} has been {state} for {}s (>= {}s) — normal catch-up should not take \
                 this long; this member may need a full resync",
                stuck_for.as_secs(),
                STUCK_STATE_DWELL.as_secs(),
            ),
            Self::FallingOffOplog {
                host,
                lag,
                oplog_window,
            } => {
                let pct = if oplog_window.as_secs() > 0 {
                    100.0 * lag.as_secs_f64() / oplog_window.as_secs_f64()
                } else {
                    100.0
                };
                format!(
                    "{host} is {}s behind the primary against a {}s oplog window ({pct:.0}% \
                     consumed) — about to fall off the oplog and need a full resync",
                    lag.as_secs(),
                    oplog_window.as_secs(),
                )
            }
            Self::OplogWindowLow { oplog_window } => format!(
                "the primary's oplog window has shrunk to {}s (floor {}s) — a lagging \
                 secondary now has less time to catch up before it falls off",
                oplog_window.as_secs(),
                OPLOG_WINDOW_FLOOR.as_secs(),
            ),
        }
    }
}

/// The pure derivation: given the primary's own oplog window, its own
/// last-applied optime, and every member's observed row (dwell already
/// resolved), which thresholds does this poll cross. No I/O, no clock reads
/// — `now`/dwell are resolved by the caller so this stays a plain function
/// of its inputs, the same discipline `rs::decide` already follows.
pub fn derive_signals(
    oplog_window: Option<Duration>,
    primary_optime_secs: Option<u32>,
    members: &[MemberObservation],
) -> Vec<ReplicationSignal> {
    let mut signals = Vec::new();

    if let Some(window) = oplog_window {
        if window < OPLOG_WINDOW_FLOOR {
            signals.push(ReplicationSignal::OplogWindowLow {
                oplog_window: window,
            });
        }
    }

    for m in members {
        if m.is_self {
            // The primary reporting on itself: never RECOVERING/STARTUP2
            // while primary, and lag against itself is always zero.
            continue;
        }

        if (m.state_str == RECOVERING || m.state_str == STARTUP2) && m.dwell >= STUCK_STATE_DWELL {
            signals.push(ReplicationSignal::StuckInState {
                host: m.host.clone(),
                state: m.state_str.clone(),
                stuck_for: m.dwell,
            });
        }

        if let (Some(window), Some(primary_secs), Some(member_secs)) =
            (oplog_window, primary_optime_secs, m.optime_secs)
        {
            if member_secs < primary_secs {
                let lag = Duration::from_secs((primary_secs - member_secs) as u64);
                let warn_at = window.mul_f64(LAG_VS_OPLOG_WINDOW_WARN_RATIO);
                if lag >= warn_at {
                    signals.push(ReplicationSignal::FallingOffOplog {
                        host: m.host.clone(),
                        lag,
                        oplog_window: window,
                    });
                }
            }
        }
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(
        host: &str,
        state_str: &str,
        optime_secs: Option<u32>,
        is_self: bool,
        dwell: Duration,
    ) -> MemberObservation {
        MemberObservation {
            host: host.to_string(),
            state_str: state_str.to_string(),
            optime_secs,
            is_self,
            dwell,
        }
    }

    const WINDOW: Duration = Duration::from_secs(2 * 3600); // 2h — comfortably above the floor.

    /// Healthy set: primary + two in-sync secondaries, plenty of oplog
    /// headroom, no member stuck. Zero signals.
    #[test]
    fn healthy_set_produces_no_signals() {
        let members = vec![
            member("mongo-1:27017", "PRIMARY", Some(1000), true, Duration::ZERO),
            member(
                "mongo-2:27017",
                "SECONDARY",
                Some(999),
                false,
                Duration::from_secs(120),
            ),
            member(
                "mongo-3:27017",
                "SECONDARY",
                Some(998),
                false,
                Duration::from_secs(120),
            ),
        ];
        let signals = derive_signals(Some(WINDOW), Some(1000), &members);
        assert!(signals.is_empty(), "{signals:?}");
    }

    /// A secondary behind by a comfortable margin (well under the warn
    /// ratio) is lagging but recoverable: no signal yet.
    #[test]
    fn lagging_but_recoverable_secondary_produces_no_falling_off_signal() {
        let lag_secs = (WINDOW.as_secs() as f64 * 0.2) as u32; // 20% of the window
        let members = vec![
            member(
                "mongo-1:27017",
                "PRIMARY",
                Some(10_000),
                true,
                Duration::ZERO,
            ),
            member(
                "mongo-2:27017",
                "SECONDARY",
                Some(10_000 - lag_secs),
                false,
                Duration::from_secs(30),
            ),
        ];
        let signals = derive_signals(Some(WINDOW), Some(10_000), &members);
        assert!(signals.is_empty(), "{signals:?}");
    }

    /// A secondary whose lag has eaten past the warn ratio of the oplog
    /// window is about to fall off (or already has) — the condition the
    /// task called out as the one that matters most.
    #[test]
    fn secondary_past_the_warn_ratio_falls_off_the_oplog() {
        let lag_secs = (WINDOW.as_secs() as f64 * 0.9) as u32; // 90% of the window
        let members = vec![
            member(
                "mongo-1:27017",
                "PRIMARY",
                Some(10_000),
                true,
                Duration::ZERO,
            ),
            member(
                "mongo-2:27017",
                "SECONDARY",
                Some(10_000 - lag_secs),
                false,
                Duration::from_secs(30),
            ),
        ];
        let signals = derive_signals(Some(WINDOW), Some(10_000), &members);
        assert_eq!(
            signals,
            vec![ReplicationSignal::FallingOffOplog {
                host: "mongo-2:27017".to_string(),
                lag: Duration::from_secs(lag_secs as u64),
                oplog_window: WINDOW,
            }]
        );
    }

    /// Lag at exactly 100% of the window (the member has, by this measure,
    /// already fallen off) still reports — the ratio is a floor, not a cap.
    #[test]
    fn lag_at_the_full_window_still_reports() {
        let members = vec![
            member(
                "mongo-1:27017",
                "PRIMARY",
                Some(10_000),
                true,
                Duration::ZERO,
            ),
            member(
                "mongo-2:27017",
                "SECONDARY",
                Some(10_000 - WINDOW.as_secs() as u32),
                false,
                Duration::from_secs(30),
            ),
        ];
        let signals = derive_signals(Some(WINDOW), Some(10_000), &members);
        assert!(matches!(
            signals.as_slice(),
            [ReplicationSignal::FallingOffOplog { .. }]
        ));
    }

    /// A member stuck in RECOVERING past the dwell reports, regardless of
    /// its optime (it may have none yet).
    #[test]
    fn stuck_recovering_past_dwell_reports() {
        let members = vec![
            member(
                "mongo-1:27017",
                "PRIMARY",
                Some(10_000),
                true,
                Duration::ZERO,
            ),
            member(
                "mongo-2:27017",
                RECOVERING,
                None,
                false,
                STUCK_STATE_DWELL + Duration::from_secs(1),
            ),
        ];
        let signals = derive_signals(Some(WINDOW), Some(10_000), &members);
        assert_eq!(
            signals,
            vec![ReplicationSignal::StuckInState {
                host: "mongo-2:27017".to_string(),
                state: RECOVERING.to_string(),
                stuck_for: STUCK_STATE_DWELL + Duration::from_secs(1),
            }]
        );
    }

    /// STARTUP2 is watched the same way as RECOVERING.
    #[test]
    fn stuck_startup2_past_dwell_reports() {
        let members = vec![member(
            "mongo-2:27017",
            STARTUP2,
            None,
            false,
            STUCK_STATE_DWELL,
        )];
        let signals = derive_signals(Some(WINDOW), None, &members);
        assert_eq!(
            signals,
            vec![ReplicationSignal::StuckInState {
                host: "mongo-2:27017".to_string(),
                state: STARTUP2.to_string(),
                stuck_for: STUCK_STATE_DWELL,
            }]
        );
    }

    /// A member freshly RECOVERING (a normal 5-second transition, per the
    /// task's own framing) must not report: it has not held the state long
    /// enough to be distinguished from routine catch-up.
    #[test]
    fn a_fresh_transient_state_is_not_stuck() {
        let members = vec![member(
            "mongo-2:27017",
            RECOVERING,
            None,
            false,
            Duration::from_secs(5),
        )];
        let signals = derive_signals(Some(WINDOW), None, &members);
        assert!(signals.is_empty(), "{signals:?}");
    }

    /// The primary's own row is never reported on, even if (implausibly) it
    /// were seen as RECOVERING or its optime were momentarily behind itself.
    #[test]
    fn the_primary_never_reports_on_its_own_row() {
        let members = vec![member(
            "mongo-1:27017",
            RECOVERING,
            Some(1),
            true,
            STUCK_STATE_DWELL * 2,
        )];
        let signals = derive_signals(Some(WINDOW), Some(10_000), &members);
        assert!(signals.is_empty(), "{signals:?}");
    }

    /// An oplog window under the floor reports even with no lagging member —
    /// it is a set-wide risk factor, not a per-member one.
    #[test]
    fn oplog_window_under_the_floor_reports() {
        let small_window = OPLOG_WINDOW_FLOOR - Duration::from_secs(1);
        let members = vec![member(
            "mongo-1:27017",
            "PRIMARY",
            Some(10_000),
            true,
            Duration::ZERO,
        )];
        let signals = derive_signals(Some(small_window), Some(10_000), &members);
        assert_eq!(
            signals,
            vec![ReplicationSignal::OplogWindowLow {
                oplog_window: small_window
            }]
        );
    }

    /// A window exactly at the floor does not report — the floor is the
    /// last acceptable value, not the first bad one.
    #[test]
    fn oplog_window_exactly_at_the_floor_does_not_report() {
        let members = vec![member(
            "mongo-1:27017",
            "PRIMARY",
            Some(10_000),
            true,
            Duration::ZERO,
        )];
        let signals = derive_signals(Some(OPLOG_WINDOW_FLOOR), Some(10_000), &members);
        assert!(signals.is_empty(), "{signals:?}");
    }

    /// An unreadable oplog window (`None`) must not crash the derivation and
    /// must not manufacture a low-window signal out of missing data — an
    /// absent value is not evidence of a small one, and lag-vs-window
    /// signals are simply skipped when the window is unknown.
    #[test]
    fn an_unreadable_oplog_window_produces_no_window_or_lag_signals() {
        let members = vec![member(
            "mongo-2:27017",
            "SECONDARY",
            Some(1),
            false,
            Duration::from_secs(30),
        )];
        let signals = derive_signals(None, Some(1_000_000), &members);
        assert!(signals.is_empty(), "{signals:?}");
    }

    /// Every signal from one poll gets a distinct dedupe key per (kind,
    /// host) so a stuck member and a falling-off member never share an
    /// incident identity and suppress each other.
    #[test]
    fn dedupe_keys_are_distinct_per_kind_and_host() {
        let a = ReplicationSignal::StuckInState {
            host: "mongo-2:27017".into(),
            state: RECOVERING.to_string(),
            stuck_for: STUCK_STATE_DWELL,
        };
        let b = ReplicationSignal::FallingOffOplog {
            host: "mongo-2:27017".into(),
            lag: Duration::from_secs(1),
            oplog_window: WINDOW,
        };
        let c = ReplicationSignal::OplogWindowLow {
            oplog_window: WINDOW,
        };
        let keys: std::collections::HashSet<_> = [a.dedupe_key(), b.dedupe_key(), c.dedupe_key()]
            .into_iter()
            .collect();
        assert_eq!(keys.len(), 3, "expected three distinct dedupe keys");
    }

    /// Every message renders the concrete numbers, not just the label — an
    /// operator reading the telemetry stream needs the seconds, not only
    /// "some member is stuck".
    #[test]
    fn messages_carry_the_concrete_numbers() {
        let stuck = ReplicationSignal::StuckInState {
            host: "mongo-2:27017".into(),
            state: RECOVERING.to_string(),
            stuck_for: Duration::from_secs(1000),
        };
        assert!(stuck.message().contains("1000s"));
        assert!(stuck.message().contains("mongo-2:27017"));

        let falling_off = ReplicationSignal::FallingOffOplog {
            host: "mongo-3:27017".into(),
            lag: Duration::from_secs(90),
            oplog_window: Duration::from_secs(100),
        };
        assert!(falling_off.message().contains("90s"));
        assert!(falling_off.message().contains("100s"));
        assert!(falling_off.message().contains("90%"));

        let low_window = ReplicationSignal::OplogWindowLow {
            oplog_window: Duration::from_secs(1800),
        };
        assert!(low_window.message().contains("1800s"));
    }

    #[test]
    fn member_state_tracker_resets_the_clock_on_a_state_change() {
        let mut tracker = MemberStateTracker::new();
        let t0 = Instant::now();
        assert_eq!(tracker.observe("mongo-2", RECOVERING, t0), Duration::ZERO);
        assert_eq!(
            tracker.observe("mongo-2", RECOVERING, t0 + Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        // A state change resets the clock, even for a state seen before.
        assert_eq!(
            tracker.observe("mongo-2", "SECONDARY", t0 + Duration::from_secs(31)),
            Duration::ZERO
        );
        assert_eq!(
            tracker.observe("mongo-2", RECOVERING, t0 + Duration::from_secs(60)),
            Duration::ZERO
        );
    }

    #[test]
    fn member_state_tracker_forgets_hosts_no_longer_in_the_membership_view() {
        let mut tracker = MemberStateTracker::new();
        let t0 = Instant::now();
        tracker.observe("mongo-2", RECOVERING, t0);
        tracker.retain_known(&["mongo-3".to_string()]);
        // Re-observed under the same name after being pruned and re-added:
        // starts fresh, not at whatever the forgotten clock would have read.
        assert_eq!(
            tracker.observe("mongo-2", RECOVERING, t0 + Duration::from_secs(1000)),
            Duration::ZERO
        );
    }
}
