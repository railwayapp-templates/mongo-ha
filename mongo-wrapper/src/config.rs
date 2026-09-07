//! Configuration for the MongoDB replica set node wrapper.
//!
//! Two modes, decided by RS_SEEDS:
//!   - unset  → standalone passthrough: mongod runs with no `--replSet` at
//!     all; /health is a real liveness probe and /role answers 200 while
//!     mongod is alive (there is nothing to fence against). A stale replica
//!     set config left on the volume by a previous HA life is dropped, the
//!     documented way (see rs::drop_stale_replset_config).
//!   - set    → HA mode: mongod runs with `--replSet RS_NAME --keyFile ...`
//!     (keyfile implies authentication), and the orchestrator decides
//!     initiate-vs-join. RS_KEY is required — every member derives the same
//!     keyfile from it.
//!
//! MONGO_INITDB_ROOT_USERNAME / MONGO_INITDB_ROOT_PASSWORD are required in
//! both modes: the upstream docker-entrypoint.sh initializes the root account
//! from them on a fresh data directory, and the wrapper authenticates its own
//! local admin commands with them.

use anyhow::{bail, Context, Result};
use common::{ConfigExt, RailwayEnv};

pub struct Config {
    /// Root account the upstream entrypoint creates on a fresh data dir and
    /// the wrapper authenticates as. Both reach docker-entrypoint.sh through
    /// the inherited process environment, never as CLI args.
    pub mongo_root_username: String,
    pub mongo_root_password: String,
    pub mongo_port: u16,
    /// Declarative HA switch (default true). The template stamps
    /// RS_ENABLED=true as its `haActiveVariable`; the revert flow strips it
    /// together with RS_SEEDS — either alone is enough to boot standalone.
    pub rs_enabled_flag: bool,
    /// Comma-separated "host:port" list of ALL replica set members (self
    /// included), in template order — the declared order is the seed-order
    /// tie-break for the initiate decision (see rs::decide).
    pub rs_seeds: Option<String>,
    /// The replica set name (`--replSet`). Baked into the config persisted in
    /// mongod's `local` database, so once a set has run it must never change;
    /// the template stamps it explicitly.
    pub rs_name: String,
    /// Shared secret every member derives the keyfile from (see keyfile.rs).
    /// Required in HA mode.
    pub rs_key: Option<String>,
    /// Where the derived keyfile is written. Outside the data dir on purpose:
    /// the keyfile is a function of RS_KEY, never state to preserve.
    pub keyfile_path: String,
    pub health_port: u16,
    /// This node's private Railway hostname.
    pub private_domain: String,
    /// mongod dbpath — the Railway volume mount. The runtime lock lives here
    /// so it is scoped to the dataset, not the container.
    pub data_dir: String,
    /// Timeout for a single peer /rs/state query.
    pub peer_query_timeout_ms: u64,
    /// How long the initiate decision must hold stable before the candidate
    /// actually initiates a brand-new replica set.
    pub bootstrap_dwell_seconds: u64,
    /// Overall bound on the pre-shutdown primary handoff, milliseconds
    /// (see demote_on_shutdown.rs).
    pub demote_timeout_ms: u64,
    /// How long a declared peer's NAME must be authoritatively gone
    /// (continuous NXDOMAIN) before (a) the initiate guard stops waiting on
    /// it and (b) the primary removes it from the replica set config. Long
    /// on purpose: a redeploy passes through a no-container NXDOMAIN window,
    /// and waiving a peer that was merely mid-redeploy could initiate past
    /// the dataset that matters. See rs::GoneTracker.
    pub peer_gone_dwell_seconds: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let mongo_root_username = String::env_required("MONGO_INITDB_ROOT_USERNAME")
            .context("MONGO_INITDB_ROOT_USERNAME must be set")?;
        let mongo_root_password = String::env_required("MONGO_INITDB_ROOT_PASSWORD")
            .context("MONGO_INITDB_ROOT_PASSWORD must be set")?;

        let config = Self {
            mongo_root_username,
            mongo_root_password,
            mongo_port: u16::env_parse("MONGO_PORT", 27017),
            // Only a literal "false" disables — absence means "follow RS_SEEDS".
            rs_enabled_flag: std::env::var("RS_ENABLED").map_or(true, |v| v != "false"),
            rs_seeds: non_empty(std::env::var("RS_SEEDS").ok()),
            rs_name: String::env_or("RS_NAME", "rs0"),
            rs_key: non_empty(std::env::var("RS_KEY").ok()),
            keyfile_path: String::env_or("RS_KEYFILE_PATH", "/run/mongo-ha/keyfile"),
            health_port: u16::env_parse("HEALTH_PORT", 8080),
            private_domain: RailwayEnv::private_domain(),
            data_dir: non_empty(std::env::var("DATA_DIR").ok())
                .or_else(|| non_empty(std::env::var("RAILWAY_VOLUME_MOUNT_PATH").ok()))
                .unwrap_or_else(|| "/data/db".to_string()),
            peer_query_timeout_ms: u64::env_parse("PEER_QUERY_TIMEOUT_MS", 2000),
            bootstrap_dwell_seconds: u64::env_parse("BOOTSTRAP_DWELL_SECONDS", 15),
            demote_timeout_ms: u64::env_parse("DEMOTE_TIMEOUT_MS", 20_000),
            peer_gone_dwell_seconds: u64::env_parse("PEER_GONE_DWELL_SECONDS", 1800),
        };

        if config.rs_enabled() && config.rs_key.is_none() {
            bail!("RS_KEY must be set when RS_SEEDS is set");
        }
        if config.rs_name.is_empty() || config.rs_name.contains(char::is_whitespace) {
            bail!("RS_NAME must be a non-empty name without whitespace");
        }

        Ok(config)
    }

    pub fn rs_enabled(&self) -> bool {
        self.rs_enabled_flag && self.rs_seeds.is_some()
    }

    /// The upstream entrypoint's own "already initialized" test: any of the
    /// files a mongod dataset always carries. Checked BEFORE mongod spawns —
    /// it is the initiate tie-break's `has_data` (an adopted volume outranks
    /// fresh nodes), and it cannot be asked of a `--replSet` member with no
    /// config, which refuses every read command.
    pub fn datadir_is_initialized(&self) -> bool {
        let dir = std::path::Path::new(&self.data_dir);
        ["WiredTiger", "journal", "local.0", "storage.bson"]
            .iter()
            .any(|f| dir.join(f).exists())
    }

    /// This node as the replica set names it: `host:port`. Must match the
    /// entry the template stamps into every RS_SEEDS.
    pub fn node_id(&self) -> String {
        format!("{}:{}", self.private_domain, self.mongo_port)
    }

    /// The bare hostnames from RS_SEEDS, in declared order.
    pub fn seed_hosts(&self) -> Vec<String> {
        self.rs_seeds
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(|entry| entry.trim().split(':').next().unwrap_or("").to_string())
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Peer hostnames — every declared seed except this node.
    pub fn peer_hosts(&self) -> Vec<String> {
        self.seed_hosts()
            .into_iter()
            .filter(|h| !h.eq_ignore_ascii_case(&self.private_domain))
            .collect()
    }

    /// A host's 0-based position in the declared seed order; None when it is
    /// not declared at all (a peer that scaled in after this node's RS_SEEDS
    /// was stamped, or a ghost from a scale-down).
    pub fn seed_rank(&self, host: &str) -> Option<usize> {
        self.seed_hosts()
            .iter()
            .position(|h| h.eq_ignore_ascii_case(host))
    }

    pub fn my_seed_rank(&self) -> Option<usize> {
        self.seed_rank(&self.private_domain)
    }
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_seeds(private_domain: &str, seeds: Option<&str>) -> Config {
        Config {
            mongo_root_username: "mongo".into(),
            mongo_root_password: "pw".into(),
            mongo_port: 27017,
            rs_enabled_flag: true,
            rs_seeds: seeds.map(str::to_string),
            rs_name: "rs0".into(),
            rs_key: Some("k".into()),
            keyfile_path: "/run/mongo-ha/keyfile".into(),
            health_port: 8080,
            private_domain: private_domain.into(),
            data_dir: "/data/db".into(),
            peer_query_timeout_ms: 2000,
            bootstrap_dwell_seconds: 15,
            demote_timeout_ms: 20_000,
            peer_gone_dwell_seconds: 1800,
        }
    }

    #[test]
    fn seeds_parse_in_declared_order_and_exclude_self() {
        let c = config_with_seeds(
            "mongo-2",
            Some("mongo-1:27017, mongo-2:27017,mongo-3:27017"),
        );
        assert_eq!(c.seed_hosts(), vec!["mongo-1", "mongo-2", "mongo-3"]);
        assert_eq!(c.peer_hosts(), vec!["mongo-1", "mongo-3"]);
        assert_eq!(c.my_seed_rank(), Some(1));
        assert_eq!(c.seed_rank("mongo-3"), Some(2));
        assert_eq!(c.seed_rank("mongo-9"), None);
        assert_eq!(c.node_id(), "mongo-2:27017");
        assert!(c.rs_enabled());
    }

    #[test]
    fn no_seeds_means_standalone() {
        let c = config_with_seeds("mongo-1", None);
        assert!(!c.rs_enabled());
        assert!(c.seed_hosts().is_empty());
        assert_eq!(c.my_seed_rank(), None);
    }

    #[test]
    fn rs_enabled_false_overrides_seeds() {
        let mut c = config_with_seeds("mongo-1", Some("mongo-1:27017,mongo-2:27017"));
        c.rs_enabled_flag = false;
        assert!(!c.rs_enabled());
    }
}
