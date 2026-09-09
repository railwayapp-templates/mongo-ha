//! Local MongoDB access for the wrapper — root connection over the loopback.
//!
//! Every command the wrapper issues goes through here. Short reads carry a
//! 2s timeout so a hung mongod degrades the health endpoints to fail-closed
//! 503s instead of hanging them; membership operations (an initiate, a
//! reconfig, a step-down that waits for a secondary to catch up) get their
//! own, longer bounds at the call site.
//!
//! ## The pooled session and initial sync
//!
//! The driver authenticates a pooled connection once, when it is established,
//! and mongod keeps that connection's user in a session cache. On a member that
//! joined by INITIAL SYNC the pool logged in as the root user docker-entrypoint
//! created on this node's fresh volume; the sync then drops `admin` and clones
//! the set's copy, whose root document carries a different userId. The next
//! write to `admin.system.users` invalidates mongod's user cache, the session
//! refresh finds the id changed and logs the connection out
//! (`AuthorizationManagerImpl::reacquireUser`: "User id from privilege document
//! does not match user id in session" → UserNotFound → server log id 20245
//! "Removed deleted user from session cache of user information"), and from
//! then on every command on that connection fails with code 13 "requires
//! authentication" — while a fresh connection with the same password
//! authenticates fine. The driver re-authenticates only on code 391 (OIDC),
//! never on 13. So `admin` treats a code 13 as a lost session: it rebuilds the
//! pool with the active password, once per observed pool generation, and
//! retries the command once.

use anyhow::{anyhow, bail, Context, Result};
use mongodb::bson::{doc, Bson, Document};
use mongodb::error::ErrorKind;
use mongodb::options::{
    ClientOptions, Credential, ReadPreference, SelectionCriteria, ServerAddress,
};
use mongodb::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::warn;

const SHORT_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
/// A reconfig may wait for the previous config to commit across a majority.
const RECONFIG_TIMEOUT: Duration = Duration::from_secs(30);

/// Server error codes this wrapper reasons about, by name — the numbers are
/// mongod's, stable across every version this image wraps.
pub mod codes {
    /// `replSetGetStatus`/`replSetGetConfig` on a member with no config yet.
    pub const NOT_YET_INITIALIZED: i32 = 94;
    /// `replSetInitiate` on a node that already holds a config.
    pub const ALREADY_INITIALIZED: i32 = 23;
    /// Reconfig against a stale config version, or an incompatible change.
    pub const NEW_CONFIG_INCOMPATIBLE: i32 = 103;
    /// A reconfig while the previous one has not committed yet.
    pub const CONFIGURATION_IN_PROGRESS: i32 = 109;
    /// The command needs a primary and this node is not one (anymore).
    pub const NOT_WRITABLE_PRIMARY: i32 = 10107;
    /// `replSetStepDown` found no secondary caught up within the window.
    pub const EXCEEDED_TIME_LIMIT: i32 = 262;
    /// The connection carries no authenticated user (or lacks a privilege).
    /// On a pool that authenticated at connection time this means mongod
    /// logged the session out underneath the driver — see the module doc.
    pub const UNAUTHORIZED: i32 = 13;
}

/// What `hello` said about the server behind this connection.
#[derive(Debug, Clone, Default)]
pub struct Hello {
    pub is_writable_primary: bool,
    pub secondary: bool,
    /// Present once the node holds a replica set config.
    pub set_name: Option<String>,
    /// Set by a node started with `--replSet` that has no config yet.
    pub isreplicaset: bool,
    /// `host:port` of the primary this node sees.
    pub primary: Option<String>,
}

impl Hello {
    /// mongod is running with `--replSet` (initiated or not).
    pub fn replication_enabled(&self) -> bool {
        self.set_name.is_some() || self.isreplicaset
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RsMember {
    pub id: i64,
    /// `host:port` as the config names it.
    pub host: String,
    pub state: i32,
    pub state_str: String,
    pub healthy: bool,
    pub is_self: bool,
}

/// The node's replica set status, or the fact that it has none.
#[derive(Debug, Clone)]
pub enum RsStatus {
    NotInitialized,
    Active {
        set_name: String,
        my_state: i32,
        my_state_str: String,
        members: Vec<RsMember>,
        /// `votingMembersCount`: members whose vote counts right now. A member
        /// added seconds ago is `newlyAdded` (non-voting) until its initial
        /// sync completes and the primary's automatic reconfig commits — a
        /// set can look fully healthy and still be unable to elect. Absent on
        /// servers that do not report it.
        voting_members: Option<usize>,
    },
}

/// mongod's own state codes, by name.
pub mod states {
    pub const PRIMARY: i32 = 1;
}

/// The pooled client and how many times it has been replaced. The generation
/// lets concurrent callers that all saw the same logged-out session agree on
/// ONE rebuild instead of each replacing the other's fresh pool.
struct Pool {
    client: Client,
    generation: u64,
}

#[derive(Clone)]
pub struct Mongo {
    host: String,
    port: u16,
    username: String,
    /// The password the pooled client currently authenticates with; kept so
    /// a throwaway client (fresh authorization, see drop_stale_replset_config)
    /// and a rebuilt pool can be built with the same identity.
    password: Arc<RwLock<String>>,
    /// Swappable: built with the boot-time password (the pin's, when one
    /// exists), replaced by the credential resolver once it has proven a
    /// different password against the live server (see auth_pin.rs), and
    /// rebuilt when mongod logs its session out (see the module doc). Every
    /// clone of this handle observes the swap.
    pool: Arc<RwLock<Pool>>,
}

const PASSWORD_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of a single-connection authentication probe, distinguishing "the
/// password is wrong" from "mongod is not up yet" — the credential resolver
/// must never treat a booting server as a credential verdict.
#[derive(Debug)]
pub enum PasswordProbe {
    Works,
    AccessDenied,
    NotReady(String),
}

/// Try one throwaway connection with the given credentials. Kept off the
/// shared pool on purpose: probing candidates must not poison it.
pub async fn probe_password(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> PasswordProbe {
    let client = client_for(host, port, username, password, true);
    let attempt = tokio::time::timeout(
        PASSWORD_PROBE_TIMEOUT,
        client.database("admin").run_command(doc! { "ping": 1 }),
    )
    .await;
    let outcome = match attempt {
        Ok(Ok(_)) => PasswordProbe::Works,
        Ok(Err(e)) => match e.kind.as_ref() {
            ErrorKind::Authentication { .. } => PasswordProbe::AccessDenied,
            // 18 = AuthenticationFailed, the server's own verdict.
            ErrorKind::Command(c) if c.code == 18 => PasswordProbe::AccessDenied,
            _ => PasswordProbe::NotReady(e.to_string()),
        },
        Err(_) => PasswordProbe::NotReady("probe timed out".to_string()),
    };
    client.shutdown().await;
    outcome
}

/// The error code of a server-side command failure, if that is what `e` is.
pub fn command_error_code(e: &anyhow::Error) -> Option<i32> {
    e.downcast_ref::<mongodb::error::Error>()
        .and_then(|e| match e.kind.as_ref() {
            ErrorKind::Command(c) => Some(c.code),
            _ => None,
        })
}

/// A reply saying the connection is not authenticated (code 13). Code 13 also
/// covers a genuine privilege refusal; that one survives the single retry a
/// rebuilt pool gets and is returned as is.
pub fn is_lost_session(e: &anyhow::Error) -> bool {
    command_error_code(e) == Some(codes::UNAUTHORIZED)
}

/// One admin command on a given client, bounded by `timeout`.
async fn run_admin(
    client: &Client,
    command: Document,
    timeout: Duration,
    name: &str,
) -> Result<Document> {
    tokio::time::timeout(timeout, client.database("admin").run_command(command))
        .await
        .map_err(|_| anyhow!("{name} timed out after {timeout:?}"))?
        .map_err(|e| anyhow::Error::new(e).context(format!("{name} failed")))
}

fn client_for(host: &str, port: u16, username: &str, password: &str, direct: bool) -> Client {
    let credential = Credential::builder()
        .username(username.to_string())
        .password(password.to_string())
        .source("admin".to_string())
        .build();
    let options = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host: host.to_string(),
            port: Some(port),
        }])
        .direct_connection(direct)
        // Every connection here is direct, to one server that may well be a
        // SECONDARY — and a secondary refuses plain reads (listDatabases,
        // local.system.replset) unless the read preference says anything but
        // `primary`. PrimaryPreferred keeps the semantics on a primary and
        // unlocks the same reads on a secondary.
        .selection_criteria(SelectionCriteria::ReadPreference(
            ReadPreference::PrimaryPreferred {
                options: Default::default(),
            },
        ))
        .credential(credential)
        .app_name("mongo-wrapper".to_string())
        .server_selection_timeout(SHORT_COMMAND_TIMEOUT)
        .connect_timeout(SHORT_COMMAND_TIMEOUT)
        .build();
    // `with_options` only fails on structurally invalid options; ours are
    // built above, so a failure here is a programming error.
    Client::with_options(options).expect("static client options are valid")
}

/// Parse a `host:port` member address; the port defaults to 27017 when
/// absent, as mongod itself does.
pub fn split_host_port(addr: &str) -> (String, u16) {
    match addr.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || h.starts_with('[') => (
            h.trim_matches(|c| c == '[' || c == ']').to_string(),
            p.parse().unwrap_or(27017),
        ),
        _ => (addr.to_string(), 27017),
    }
}

impl Mongo {
    /// The wrapper's own connection to the mongod it supervises. Lazy: no
    /// socket is opened until the first command.
    pub fn connect_local(port: u16, username: &str, password: &str) -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port,
            username: username.to_string(),
            password: Arc::new(RwLock::new(password.to_string())),
            pool: Arc::new(RwLock::new(Pool {
                client: client_for("127.0.0.1", port, username, password, true),
                generation: 0,
            })),
        }
    }

    /// Replace the pooled client with one authenticating as `password`. The
    /// credential resolver calls this once a candidate is PROVEN against the
    /// live server, never speculatively.
    pub async fn swap_password(&self, password: &str) {
        let fresh = client_for(&self.host, self.port, &self.username, password, true);
        let old = {
            let mut pool = self.pool.write().await;
            *self.password.write().await = password.to_string();
            pool.generation += 1;
            std::mem::replace(&mut pool.client, fresh)
        };
        old.shutdown().await;
    }

    /// The pooled client and the generation it belongs to.
    async fn pooled(&self) -> (Client, u64) {
        let pool = self.pool.read().await;
        (pool.client.clone(), pool.generation)
    }

    /// Rebuild the pool after a command on generation `observed` came back
    /// Unauthorized (see the module doc). A caller that lost the race — the
    /// pool is already past that generation — does nothing and retries on
    /// the pool it finds.
    async fn reauthenticate(&self, observed: u64) {
        let old = {
            let mut pool = self.pool.write().await;
            if pool.generation != observed {
                return;
            }
            let password = self.password.read().await.clone();
            let fresh = client_for(&self.host, self.port, &self.username, &password, true);
            pool.generation += 1;
            warn!(
                host = %self.host,
                generation = pool.generation,
                "mongod dropped the pooled connection's authenticated session (code 13); rebuilt the pool with the active password"
            );
            std::mem::replace(&mut pool.client, fresh)
        };
        old.shutdown().await;
    }

    /// Probe this handle's own server with a candidate password.
    pub async fn probe_local_password(&self, password: &str) -> PasswordProbe {
        probe_password(&self.host, self.port, &self.username, password).await
    }

    /// A direct connection to another member, for the operations that must
    /// run ON the primary (adding ourselves, a step-down, a freeze).
    pub fn connect_member(addr: &str, username: &str, password: &str) -> Self {
        let (host, port) = split_host_port(addr);
        Self {
            pool: Arc::new(RwLock::new(Pool {
                client: client_for(&host, port, username, password, true),
                generation: 0,
            })),
            host,
            port,
            username: username.to_string(),
            password: Arc::new(RwLock::new(password.to_string())),
        }
    }

    async fn admin(&self, command: Document, timeout: Duration) -> Result<Document> {
        let name = command
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "?".to_string());
        let (client, generation) = self.pooled().await;
        match run_admin(&client, command.clone(), timeout, &name).await {
            Err(e) if is_lost_session(&e) => {
                // mongod logged this pooled connection out (see the module
                // doc); a fresh pool authenticates again with the active
                // password. Retried once: a code 13 that survives a fresh
                // authentication is a real authorization verdict.
                self.reauthenticate(generation).await;
                let (client, _) = self.pooled().await;
                run_admin(&client, command, timeout, &name).await
            }
            outcome => outcome,
        }
    }

    pub async fn ping(&self) -> Result<()> {
        self.admin(doc! { "ping": 1 }, SHORT_COMMAND_TIMEOUT)
            .await?;
        Ok(())
    }

    pub async fn hello(&self) -> Result<Hello> {
        let d = self
            .admin(doc! { "hello": 1 }, SHORT_COMMAND_TIMEOUT)
            .await?;
        Ok(Hello {
            is_writable_primary: d.get_bool("isWritablePrimary").unwrap_or(false),
            secondary: d.get_bool("secondary").unwrap_or(false),
            set_name: d.get_str("setName").ok().map(str::to_string),
            isreplicaset: d.get_bool("isreplicaset").unwrap_or(false),
            primary: d.get_str("primary").ok().map(str::to_string),
        })
    }

    pub async fn rs_status(&self) -> Result<RsStatus> {
        match self
            .admin(doc! { "replSetGetStatus": 1 }, SHORT_COMMAND_TIMEOUT)
            .await
        {
            Ok(d) => {
                let members: Vec<RsMember> = d
                    .get_array("members")
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Bson::as_document)
                            .map(|m| RsMember {
                                id: bson_int(m.get("_id")).unwrap_or(-1),
                                host: m.get_str("name").unwrap_or("").to_string(),
                                state: bson_int(m.get("state")).unwrap_or(-1) as i32,
                                state_str: m.get_str("stateStr").unwrap_or("").to_string(),
                                healthy: m.get_f64("health").map(|h| h >= 1.0).unwrap_or(false)
                                    || bson_int(m.get("health")).map(|h| h >= 1).unwrap_or(false),
                                is_self: m.get_bool("self").unwrap_or(false),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(RsStatus::Active {
                    set_name: d.get_str("set").unwrap_or("").to_string(),
                    my_state: bson_int(d.get("myState")).unwrap_or(-1) as i32,
                    my_state_str: members
                        .iter()
                        .find(|m| m.is_self)
                        .map(|m| m.state_str.clone())
                        .unwrap_or_default(),
                    members,
                    voting_members: bson_int(d.get("votingMembersCount"))
                        .map(|n| n.max(0) as usize),
                })
            }
            Err(e) if command_error_code(&e) == Some(codes::NOT_YET_INITIALIZED) => {
                Ok(RsStatus::NotInitialized)
            }
            Err(e) => Err(e),
        }
    }

    /// The current replica set config document (`replSetGetConfig`).
    pub async fn rs_config(&self) -> Result<Document> {
        let d = self
            .admin(doc! { "replSetGetConfig": 1 }, SHORT_COMMAND_TIMEOUT)
            .await?;
        d.get_document("config")
            .cloned()
            .context("replSetGetConfig answered without a config")
    }

    /// Initiate a brand-new single-member set with this node as member 0.
    pub async fn rs_initiate(&self, set_name: &str, self_host: &str) -> Result<()> {
        let config = doc! {
            "_id": set_name,
            "version": 1,
            "members": [ { "_id": 0, "host": self_host } ],
        };
        self.admin(doc! { "replSetInitiate": config }, RECONFIG_TIMEOUT)
            .await?;
        Ok(())
    }

    /// Apply a new config (safe reconfig, `force: false`). The caller bumps
    /// `version`; mongod refuses a stale one with NEW_CONFIG_INCOMPATIBLE.
    pub async fn rs_reconfig(&self, config: Document) -> Result<()> {
        self.admin(
            doc! { "replSetReconfig": config, "force": false },
            RECONFIG_TIMEOUT,
        )
        .await?;
        Ok(())
    }

    /// Step this primary down, waiting up to `catchup_secs` for a secondary
    /// to catch up so the handoff loses nothing; the node then refuses to
    /// seek election for `stepdown_secs`.
    pub async fn step_down(&self, stepdown_secs: i64, catchup_secs: i64) -> Result<()> {
        let bound = Duration::from_secs(catchup_secs as u64 + 5);
        self.admin(
            doc! {
                "replSetStepDown": stepdown_secs,
                "secondaryCatchUpPeriodSecs": catchup_secs,
            },
            bound,
        )
        .await?;
        Ok(())
    }

    /// Keep this secondary from seeking election for `secs` (0 unfreezes).
    pub async fn freeze(&self, secs: i64) -> Result<()> {
        self.admin(doc! { "replSetFreeze": secs }, SHORT_COMMAND_TIMEOUT)
            .await?;
        Ok(())
    }

    /// Standalone mode only: a volume that previously ran as a replica set
    /// member still carries that set's config in `local.system.replset`, and
    /// a later re-conversion would load it — with the OLD membership — the
    /// moment mongod runs with `--replSet` again. The documented way back to
    /// a clean standalone is to drop the `local` database; this does exactly
    /// that, and only when such a config exists. Returns whether it did.
    ///
    /// The `root` role carries no `dropDatabase` on `local` (its
    /// dbAdminAnyDatabase excludes `local` and `config`; the first CI run
    /// hit `Unauthorized` here), so the drop runs under a temporary
    /// maintenance role: created, granted to this user, used from a fresh
    /// connection, then revoked and dropped again — no artifact stays behind.
    pub async fn drop_stale_replset_config(&self) -> Result<bool> {
        let count = tokio::time::timeout(
            SHORT_COMMAND_TIMEOUT,
            self.pooled()
                .await
                .0
                .database("local")
                .collection::<Document>("system.replset")
                .count_documents(doc! {}),
        )
        .await
        .map_err(|_| anyhow!("counting local.system.replset timed out"))?
        .context("counting local.system.replset failed")?;
        if count == 0 {
            return Ok(false);
        }

        const ROLE: &str = "railwayLocalMaintenance";
        let role_ref = doc! { "role": ROLE, "db": "admin" };
        match self
            .admin(
                doc! {
                    "createRole": ROLE,
                    "privileges": [ {
                        "resource": { "db": "local", "collection": "" },
                        "actions": [ "dropDatabase", "dropCollection" ],
                    } ],
                    "roles": [],
                },
                SHORT_COMMAND_TIMEOUT,
            )
            .await
        {
            Ok(_) => {}
            // 51002 DuplicateKey: the role is left over from an interrupted
            // earlier attempt; granting it below is all that matters.
            Err(e) if command_error_code(&e) == Some(51002) => {}
            Err(e) => return Err(e).context("creating the local-maintenance role"),
        }
        self.admin(
            doc! { "grantRolesToUser": self.username.clone(), "roles": [ role_ref.clone() ] },
            SHORT_COMMAND_TIMEOUT,
        )
        .await
        .context("granting the local-maintenance role")?;

        // A fresh connection picks the new privilege up unconditionally (the
        // server invalidates its user cache on a grant, but a new session is
        // the version of that guarantee this code does not have to trust).
        let password = self.password.read().await.clone();
        let fresh = client_for(&self.host, self.port, &self.username, &password, true);
        let dropped = tokio::time::timeout(RECONFIG_TIMEOUT, fresh.database("local").drop())
            .await
            .map_err(|_| anyhow!("dropping the local database timed out"))
            .and_then(|r| r.context("dropping the local database failed"));
        fresh.shutdown().await;

        // Best effort: the role's job is done either way, and a failure to
        // clean up must not hide the drop's own verdict.
        let _ = self
            .admin(
                doc! { "revokeRolesFromUser": self.username.clone(), "roles": [ role_ref ] },
                SHORT_COMMAND_TIMEOUT,
            )
            .await;
        let _ = self
            .admin(doc! { "dropRole": ROLE }, SHORT_COMMAND_TIMEOUT)
            .await;

        dropped.map(|_| true)
    }

    /// Raw admin command, for the few call sites that need something not
    /// modeled above (test hooks, diagnostics).
    #[allow(dead_code)]
    pub async fn run_admin(&self, command: Document) -> Result<Document> {
        self.admin(command, RECONFIG_TIMEOUT).await
    }
}

fn bson_int(v: Option<&Bson>) -> Option<i64> {
    match v {
        Some(Bson::Int32(i)) => Some(*i as i64),
        Some(Bson::Int64(i)) => Some(*i),
        Some(Bson::Double(f)) => Some(*f as i64),
        _ => None,
    }
}

/// Build the next config from the current one: bump `version`, apply `edit`
/// to the members array. `_id` and every other top-level setting are kept —
/// a reconfig must carry the whole config, not a patch.
pub fn next_config(current: &Document, edit: impl FnOnce(&mut Vec<Bson>)) -> Result<Document> {
    let mut next = current.clone();
    let version = bson_int(current.get("version")).context("config has no version")?;
    next.insert("version", Bson::Int64(version + 1));
    // `term` is the primary's to set: sending back the one we read makes the
    // reconfig fail the moment an election happened in between.
    next.remove("term");
    let mut members: Vec<Bson> = current
        .get_array("members")
        .context("config has no members")?
        .clone();
    edit(&mut members);
    if members.is_empty() {
        bail!("refusing to produce a config with no members");
    }
    next.insert("members", Bson::Array(members));
    Ok(next)
}

/// The config with `host` appended as a fresh voting member (next free _id).
pub fn config_with_member_added(current: &Document, host: &str) -> Result<Document> {
    next_config(current, |members| {
        let next_id = members
            .iter()
            .filter_map(Bson::as_document)
            .filter_map(|m| bson_int(m.get("_id")))
            .max()
            .map(|id| id + 1)
            .unwrap_or(0);
        members.push(Bson::Document(doc! {
            "_id": next_id,
            "host": host,
            "priority": 1,
            "votes": 1,
        }));
    })
}

/// The config with the member at `host` removed.
pub fn config_with_member_removed(current: &Document, host: &str) -> Result<Document> {
    next_config(current, |members| {
        members.retain(|m| {
            m.as_document()
                .and_then(|d| d.get_str("host").ok())
                .map(|h| !h.eq_ignore_ascii_case(host))
                .unwrap_or(true)
        });
    })
}

/// The config with `host`'s priority set to `priority`, every other member's
/// to 1 — the switchover lever (see health_server::switchover).
#[allow(dead_code)]
pub fn config_with_priority(current: &Document, host: &str, priority: i32) -> Result<Document> {
    next_config(current, |members| {
        for m in members.iter_mut() {
            if let Bson::Document(d) = m {
                let is_target = d
                    .get_str("host")
                    .map(|h| h.eq_ignore_ascii_case(host))
                    .unwrap_or(false);
                d.insert("priority", if is_target { priority } else { 1 });
            }
        }
    })
}

/// Every `host:port` in a config.
pub fn config_member_hosts(config: &Document) -> Vec<String> {
    config
        .get_array("members")
        .map(|arr| {
            arr.iter()
                .filter_map(Bson::as_document)
                .filter_map(|m| m.get_str("host").ok())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a member view has a reachable majority — the fence /role applies
/// on top of mongod's own `isWritablePrimary`, so a primary that has just
/// lost contact with the majority answers 503 ahead of its own step-down.
pub fn has_majority(members: &[RsMember]) -> bool {
    if members.is_empty() {
        return false;
    }
    let healthy = members.iter().filter(|m| m.healthy || m.is_self).count();
    healthy * 2 > members.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(host: &str, state: i32, healthy: bool, is_self: bool) -> RsMember {
        RsMember {
            id: 0,
            host: host.into(),
            state,
            state_str: String::new(),
            healthy,
            is_self,
        }
    }

    #[test]
    fn majority_counts_self_and_healthy_members() {
        let trio = vec![
            member("a:27017", 1, true, true),
            member("b:27017", 2, true, false),
            member("c:27017", 8, false, false),
        ];
        assert!(has_majority(&trio));
        let isolated = vec![
            member("a:27017", 1, true, true),
            member("b:27017", 8, false, false),
            member("c:27017", 8, false, false),
        ];
        assert!(!has_majority(&isolated));
        assert!(!has_majority(&[]));
    }

    #[test]
    fn adding_a_member_bumps_version_and_picks_the_next_id() {
        let current = doc! {
            "_id": "rs0", "version": 3, "term": 7,
            "members": [ { "_id": 0, "host": "a:27017" }, { "_id": 4, "host": "b:27017" } ],
            "settings": { "electionTimeoutMillis": 10000 },
        };
        let next = config_with_member_added(&current, "c:27017").unwrap();
        assert_eq!(bson_int(next.get("version")), Some(4));
        assert!(
            next.get("term").is_none(),
            "term is left for the primary to set"
        );
        assert_eq!(next.get_str("_id").unwrap(), "rs0");
        assert!(
            next.get_document("settings").is_ok(),
            "other settings are carried over"
        );
        let hosts = config_member_hosts(&next);
        assert_eq!(hosts, vec!["a:27017", "b:27017", "c:27017"]);
        let added = next.get_array("members").unwrap()[2].as_document().unwrap();
        assert_eq!(bson_int(added.get("_id")), Some(5));
        assert_eq!(bson_int(added.get("votes")), Some(1));
    }

    #[test]
    fn removing_a_member_keeps_the_rest_and_refuses_to_empty_the_set() {
        let current = doc! {
            "_id": "rs0", "version": 1,
            "members": [ { "_id": 0, "host": "a:27017" }, { "_id": 1, "host": "b:27017" } ],
        };
        let next = config_with_member_removed(&current, "B:27017").unwrap();
        assert_eq!(config_member_hosts(&next), vec!["a:27017"]);
        assert!(config_with_member_removed(&next, "a:27017").is_err());
    }

    #[test]
    fn priority_edit_targets_one_member_and_resets_the_others() {
        let current = doc! {
            "_id": "rs0", "version": 1,
            "members": [
                { "_id": 0, "host": "a:27017", "priority": 5 },
                { "_id": 1, "host": "b:27017" },
            ],
        };
        let next = config_with_priority(&current, "b:27017", 2).unwrap();
        let members = next.get_array("members").unwrap();
        assert_eq!(
            bson_int(members[0].as_document().unwrap().get("priority")),
            Some(1)
        );
        assert_eq!(
            bson_int(members[1].as_document().unwrap().get("priority")),
            Some(2)
        );
    }

    #[test]
    fn host_port_splitting_handles_defaults_and_ipv6() {
        assert_eq!(split_host_port("mongo-1:27018"), ("mongo-1".into(), 27018));
        assert_eq!(split_host_port("mongo-1"), ("mongo-1".into(), 27017));
        assert_eq!(
            split_host_port("[fd12::1]:27017"),
            ("fd12::1".into(), 27017)
        );
    }

    /// A driver error carrying a server command failure with `code`, the
    /// shape `admin` sees (CommandError is non-exhaustive: built through its
    /// Deserialize impl, wrapped the way `run_admin` wraps it).
    fn server_error(code: i32, errmsg: &str) -> anyhow::Error {
        let command: mongodb::error::CommandError = mongodb::bson::from_document(doc! {
            "code": code, "codeName": "x", "errmsg": errmsg,
        })
        .unwrap();
        anyhow::Error::new(mongodb::error::Error::from(ErrorKind::Command(command)))
            .context("replSetGetStatus failed")
    }

    #[test]
    fn a_lost_session_is_code_13_and_nothing_else() {
        assert!(is_lost_session(&server_error(
            13,
            "Command replSetGetStatus requires authentication"
        )));
        assert!(!is_lost_session(&server_error(
            94,
            "no replset config has been received"
        )));
        assert!(!is_lost_session(&anyhow!(
            "replSetGetStatus timed out after 2s"
        )));
        assert_eq!(
            command_error_code(&server_error(13, "x")),
            Some(codes::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn a_lost_session_rebuilds_the_pool_once_per_generation() {
        let m = Mongo::connect_local(27017, "mongo", "pw");
        let (_, g0) = m.pooled().await;
        assert_eq!(g0, 0);
        // Two callers that observed the same logged-out generation: one
        // rebuild, not two — the second finds the pool already past it.
        m.reauthenticate(g0).await;
        m.reauthenticate(g0).await;
        assert_eq!(m.pooled().await.1, 1);
        // A stale observation after the rebuild is a no-op too.
        m.reauthenticate(g0).await;
        assert_eq!(m.pooled().await.1, 1);
        // A proven password swap is a new generation with the new identity.
        m.swap_password("other").await;
        assert_eq!(m.pooled().await.1, 2);
        assert_eq!(*m.password.read().await, "other");
    }

    #[test]
    fn hello_replication_enabled_reads_both_shapes() {
        let initiated = Hello {
            set_name: Some("rs0".into()),
            ..Default::default()
        };
        let uninitiated = Hello {
            isreplicaset: true,
            ..Default::default()
        };
        let standalone = Hello::default();
        assert!(initiated.replication_enabled());
        assert!(uninitiated.replication_enabled());
        assert!(!standalone.replication_enabled());
    }
}
