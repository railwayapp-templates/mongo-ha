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
//!
//! ## Recovering the pooled client in general
//!
//! A lost session is one way the pooled client can stop working while mongod
//! is fine; a refused authentication (code 18, or the driver's own
//! authentication failure on a fresh socket) and a client that keeps timing
//! out are others. Every command on the pooled client goes through
//! `recovering`, which classifies a failure (`classify`) and lets
//! `RecoveryPolicy` decide whether to rebuild: an authentication failure
//! rebuilds at once, a run of transport failures (timeouts, server
//! selection, I/O) rebuilds after `TRANSPORT_FAILURES_BEFORE_REBUILD`, and a
//! server verdict never does. Rebuilds back off exponentially until an
//! authenticated command succeeds again, so a credential that stays refused
//! costs one rebuild per backoff window, not one per request.

use anyhow::{anyhow, bail, Context, Result};
use mongodb::bson::{doc, Bson, Document};
use mongodb::error::ErrorKind;
use mongodb::options::{
    ClientOptions, Credential, ReadPreference, SelectionCriteria, ServerAddress,
};
use mongodb::Client;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

const SHORT_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
/// A reconfig may wait for the previous config to commit across a majority.
const RECONFIG_TIMEOUT: Duration = Duration::from_secs(30);
/// First wait after a rebuild before another may happen; doubles per rebuild
/// up to `REBUILD_BACKOFF_MAX`, and resets once an authenticated command
/// succeeds.
const REBUILD_BACKOFF_MIN: Duration = Duration::from_secs(30);
const REBUILD_BACKOFF_MAX: Duration = Duration::from_secs(300);
/// Consecutive transport failures (timeouts, server selection, I/O) on the
/// pooled client before it is rebuilt.
const TRANSPORT_FAILURES_BEFORE_REBUILD: u32 = 5;
/// The change-stream pre-images collection every replica set creates in
/// `config`; dropped with `local` on a revert (see drop_stale_replset_config).
const PREIMAGES_COLLECTION: &str = "system.preimages";

/// Server error codes this wrapper reasons about, by name — the numbers are
/// mongod's, stable across every version this image wraps.
pub mod codes {
    /// `replSetGetStatus`/`replSetGetConfig` on a member with no config yet.
    pub const NOT_YET_INITIALIZED: i32 = 94;
    /// The node holds a config it is not a member of — a peer reconfigured the
    /// set without it, so its local copy names hosts that do not include self.
    pub const INVALID_REPLICA_SET_CONFIG: i32 = 93;
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
    /// The server refused the credential outright.
    pub const AUTHENTICATION_FAILED: i32 = 18;
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
    /// Seconds since the Unix epoch of this member's last applied optime
    /// (`optime.ts`, the BSON Timestamp every member reports — not the
    /// human-readable `optimeDate`, so lag arithmetic stays in the same
    /// integer-seconds unit `Mongo::oplog_window` reads off the oplog itself).
    /// None when the member has not applied anything yet (freshly added,
    /// still in initial sync) or the server does not report it.
    pub optime_secs: Option<u32>,
}

/// Parse one `replSetGetStatus` `members[]` row. Split out from `rs_status`
/// so the shape can be fed synthetic BSON documents in tests — see
/// `replication_monitor`'s derivation tests, which build members this way
/// rather than requiring a live replica set.
fn member_from_doc(m: &Document) -> RsMember {
    RsMember {
        id: bson_int(m.get("_id")).unwrap_or(-1),
        host: m.get_str("name").unwrap_or("").to_string(),
        state: bson_int(m.get("state")).unwrap_or(-1) as i32,
        state_str: m.get_str("stateStr").unwrap_or("").to_string(),
        healthy: m.get_f64("health").map(|h| h >= 1.0).unwrap_or(false)
            || bson_int(m.get("health")).map(|h| h >= 1).unwrap_or(false),
        is_self: m.get_bool("self").unwrap_or(false),
        // mongod reports `Timestamp(0, 0)` for a member it has no optime for
        // (DOWN, STARTUP, unreachable); that is an absent optime, not 1970.
        optime_secs: m
            .get_document("optime")
            .ok()
            .and_then(|d| d.get_timestamp("ts").ok())
            .map(|ts| ts.time)
            .filter(|&secs| secs > 0),
    }
}

/// `size / maxSize` from a `collStats` reply on the oplog. Both are byte
/// counts mongod may encode as int, long or double.
fn oplog_fill_from_stats(stats: &Document) -> Option<f64> {
    let number = |key: &str| match stats.get(key) {
        Some(Bson::Int32(n)) => Some(f64::from(*n)),
        Some(Bson::Int64(n)) => Some(*n as f64),
        Some(Bson::Double(n)) => Some(*n),
        _ => None,
    };
    let (size, max) = (number("size")?, number("maxSize")?);
    (max > 0.0).then(|| size / max)
}

/// The node's replica set status, or the fact that it has none.
#[derive(Debug, Clone)]
pub enum RsStatus {
    NotInitialized,
    /// The node holds a config that does not list it: a peer reconfigured the
    /// set without it. Like `REMOVED`, only the peers' view counts now — the
    /// node has to be re-added through the current primary.
    NotAMember,
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

/// A bounded operation that ran out of time. Typed so `classify` can tell a
/// stuck client apart from a server verdict.
#[derive(Debug)]
pub struct TimedOut(pub String);

impl std::fmt::Display for TimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TimedOut {}

/// What a failed command on the pooled client says about the client itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The connection is not (or no longer) authenticated.
    Auth,
    /// The command never got a server answer: timeout, server selection, I/O.
    Transport,
    /// The server answered with a verdict; the client works.
    Verdict,
}

pub fn classify(e: &anyhow::Error) -> Failure {
    if e.downcast_ref::<TimedOut>().is_some() {
        return Failure::Transport;
    }
    match e
        .downcast_ref::<mongodb::error::Error>()
        .map(|e| e.kind.as_ref())
    {
        Some(ErrorKind::Authentication { .. }) => Failure::Auth,
        Some(ErrorKind::Command(c))
            if c.code == codes::UNAUTHORIZED || c.code == codes::AUTHENTICATION_FAILED =>
        {
            Failure::Auth
        }
        Some(
            ErrorKind::ServerSelection { .. }
            | ErrorKind::Io(_)
            | ErrorKind::ConnectionPoolCleared { .. },
        ) => Failure::Transport,
        _ => Failure::Verdict,
    }
}

/// When to rebuild the pooled client. Pure: the caller supplies `now`.
///
/// Backoff only throttles rebuilds that did not help: a rebuild arms a window
/// for its own failure kind, and only a repeat of that kind before anything
/// proves the rebuilt client works is held back. Any proof clears it, so the
/// first auth failure after the credential last worked always rebuilds at
/// once — including after a rebuild at boot, before the root user existed.
#[derive(Debug)]
struct RecoveryPolicy {
    transport_failures: u32,
    backoff: Duration,
    /// The failure kind the last rebuild was for, and when another rebuild
    /// for that kind may happen. Cleared once the rebuilt client is proven.
    pending: Option<(Failure, Instant)>,
}

impl RecoveryPolicy {
    const fn new() -> Self {
        Self {
            transport_failures: 0,
            backoff: REBUILD_BACKOFF_MIN,
            pending: None,
        }
    }

    fn proven(&mut self, authenticated: bool) {
        self.transport_failures = 0;
        match self.pending {
            // Any answer proves the transport; only an authenticated one
            // proves the credential.
            Some((Failure::Transport, _)) => self.pending = None,
            Some(_) if authenticated => self.pending = None,
            _ => {}
        }
        if self.pending.is_none() {
            self.backoff = REBUILD_BACKOFF_MIN;
        }
    }

    /// `authenticated`: the command needed an authenticated session
    /// (`hello`/`ping` do not), so a server answer to it proves the
    /// credential works.
    fn on_success(&mut self, authenticated: bool) {
        self.proven(authenticated);
    }

    /// Whether this failure should rebuild the client now.
    fn on_failure(&mut self, failure: Failure, authenticated: bool, now: Instant) -> bool {
        match failure {
            Failure::Verdict => {
                // The server answered: the client works.
                self.proven(authenticated);
                return false;
            }
            Failure::Transport => {
                self.transport_failures += 1;
                if self.transport_failures < TRANSPORT_FAILURES_BEFORE_REBUILD {
                    return false;
                }
            }
            Failure::Auth => {}
        }
        match self.pending {
            Some((kind, until)) if kind == failure && now < until => return false,
            // The previous rebuild for this kind did not fix it.
            Some((kind, _)) if kind == failure => {
                self.backoff = (self.backoff * 2).min(REBUILD_BACKOFF_MAX);
            }
            _ => self.backoff = REBUILD_BACKOFF_MIN,
        }
        self.pending = Some((failure, now + self.backoff));
        self.transport_failures = 0;
        true
    }
}

/// Commands mongod answers without an authenticated session.
fn needs_auth(name: &str) -> bool {
    !matches!(name, "hello" | "ping" | "isMaster" | "ismaster")
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
    recovery: Arc<Mutex<RecoveryPolicy>>,
}

/// The budget of one credential probe against a mongod. Also the floor a
/// joiner's keyfile fetch must respect: a peer answers `/rs/keyfile` only
/// after this probe returns (see peers::keyfile_fetch_timeout).
pub const PASSWORD_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Outcome of proving that a caller IS the root account: authenticated as
/// `username` on `admin` AND holding the `root` role there. What the keyfile
/// exchange demands (see health_server::rs_keyfile): the keyfile is the
/// `__system` credential, above every role, so a password that merely
/// authenticates some `admin` user is not enough to be handed it.
#[derive(Debug)]
pub enum RootProbe {
    Root,
    /// Wrong password, or an account without the `root` role on `admin`.
    Refused,
    NotReady(String),
}

/// One throwaway connection running `connectionStatus`: the handshake proves
/// the password, the reply names the account and roles the server actually
/// granted the session. Same "not ready is not a verdict" rule as
/// probe_password.
pub async fn probe_root(host: &str, port: u16, username: &str, password: &str) -> RootProbe {
    let client = client_for(host, port, username, password, true);
    let attempt = tokio::time::timeout(
        PASSWORD_PROBE_TIMEOUT,
        client
            .database("admin")
            .run_command(doc! { "connectionStatus": 1 }),
    )
    .await;
    let outcome = match attempt {
        Ok(Ok(reply)) if authenticated_as_root(&reply, username) => RootProbe::Root,
        Ok(Ok(_)) => RootProbe::Refused,
        Ok(Err(e)) => match e.kind.as_ref() {
            ErrorKind::Authentication { .. } => RootProbe::Refused,
            // 18 = AuthenticationFailed, the server's own verdict.
            ErrorKind::Command(c) if c.code == 18 => RootProbe::Refused,
            _ => RootProbe::NotReady(e.to_string()),
        },
        Err(_) => RootProbe::NotReady("probe timed out".to_string()),
    };
    client.shutdown().await;
    outcome
}

/// Whether a `connectionStatus` reply says the session is authenticated as
/// `username` on `admin` and holds `root` on `admin`. Both lists are read:
/// the caller named the root account, and the server must confirm that this
/// is the account it authenticated and that the account still carries the
/// role (a root user stripped of `root` is not root).
pub fn authenticated_as_root(reply: &Document, username: &str) -> bool {
    let Ok(info) = reply.get_document("authInfo") else {
        return false;
    };
    let has_admin_entry = |list: &str, field: &str, value: &str| {
        info.get_array(list)
            .map(|entries| {
                entries.iter().filter_map(Bson::as_document).any(|d| {
                    d.get_str(field).is_ok_and(|v| v == value)
                        && d.get_str("db").is_ok_and(|db| db == "admin")
                })
            })
            .unwrap_or(false)
    };
    has_admin_entry("authenticatedUsers", "user", username)
        && has_admin_entry("authenticatedUserRoles", "role", "root")
}

/// The error code of a server-side command failure, if that is what `e` is.
pub fn command_error_code(e: &anyhow::Error) -> Option<i32> {
    e.downcast_ref::<mongodb::error::Error>()
        .and_then(|e| match e.kind.as_ref() {
            ErrorKind::Command(c) => Some(c.code),
            _ => None,
        })
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
        .map_err(|_| anyhow::Error::new(TimedOut(format!("{name} timed out after {timeout:?}"))))?
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
            recovery: Arc::new(Mutex::new(RecoveryPolicy::new())),
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

    /// Rebuild the pool after a command on generation `observed` failed in a
    /// way that implicates the client (see the module doc). A caller that
    /// lost the race — the pool is already past that generation — does
    /// nothing and retries on the pool it finds. The old client is shut down
    /// in the background so a caller never waits on its in-flight work.
    async fn rebuild(&self, observed: u64, failure: Failure, error: &anyhow::Error) {
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
                ?failure,
                error = %format!("{error:#}"),
                "pooled mongod client stopped working; rebuilt the pool with the active password"
            );
            std::mem::replace(&mut pool.client, fresh)
        };
        tokio::spawn(async move { old.shutdown().await });
    }

    fn note_success(&self, authenticated: bool) {
        if let Ok(mut policy) = self.recovery.lock() {
            policy.on_success(authenticated);
        }
    }

    fn note_failure(&self, failure: Failure, authenticated: bool) -> bool {
        self.recovery
            .lock()
            .map(|mut policy| policy.on_failure(failure, authenticated, Instant::now()))
            .unwrap_or(false)
    }

    /// Run `op` on the pooled client, recovering the client when a failure
    /// implicates it (see the module doc). An authentication failure is
    /// retried once on the rebuilt client: one that survives a fresh
    /// authentication is a real verdict and is returned as is.
    async fn recovering<T, F, Fut>(&self, authenticated: bool, op: F) -> Result<T>
    where
        F: Fn(Client) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let (client, generation) = self.pooled().await;
        let error = match op(client).await {
            Ok(v) => {
                self.note_success(authenticated);
                return Ok(v);
            }
            Err(e) => e,
        };
        let failure = classify(&error);
        if !self.note_failure(failure, authenticated) {
            return Err(error);
        }
        self.rebuild(generation, failure, &error).await;
        if failure != Failure::Auth {
            return Err(error);
        }
        let (client, _) = self.pooled().await;
        match op(client).await {
            Ok(v) => {
                self.note_success(authenticated);
                Ok(v)
            }
            Err(e) => {
                self.note_failure(classify(&e), authenticated);
                Err(e)
            }
        }
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
            recovery: Arc::new(Mutex::new(RecoveryPolicy::new())),
        }
    }

    async fn admin(&self, command: Document, timeout: Duration) -> Result<Document> {
        let name = command
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "?".to_string());
        // A role update can invalidate pooled authentication before the
        // coordinator reaches this member. Only a proven staged credential
        // may replace it; edited variables are never trusted here.
        if self.host == "127.0.0.1" {
            if let Ok(config) = crate::config::Config::from_env() {
                if let Some(pending) = crate::credentials::pending_password(&config.data_dir) {
                    if *self.password.read().await != pending
                        && matches!(
                            self.probe_local_password(&pending).await,
                            PasswordProbe::Works
                        )
                    {
                        self.swap_password(&pending).await;
                    }
                }
            }
        }
        self.recovering(needs_auth(&name), |client| {
            let command = command.clone();
            let name = name.clone();
            async move { run_admin(&client, command, timeout, &name).await }
        })
        .await
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
                            .map(member_from_doc)
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
            Err(e) if command_error_code(&e) == Some(codes::INVALID_REPLICA_SET_CONFIG) => {
                Ok(RsStatus::NotAMember)
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

    /// This node's own oplog window: the wall-clock span, in whole seconds,
    /// between the oldest and newest entries in `local.oplog.rs` right now —
    /// the same computation the shell's `db.getReplicationInfo()` runs
    /// (oldest/newest by `$natural` order, diffed). `None` when the oplog is
    /// empty (a member that has taken no writes yet, or one whose oplog was
    /// just created) rather than an error: an empty oplog is not a read
    /// failure.
    ///
    /// A raw collection read, not an admin command, because there is no
    /// `replSetGetStatus`-style command for this — the shell helper itself
    /// queries the collection directly. Reads `local` the same way
    /// `drop_stale_replset_config`'s count already does: the `root` role
    /// includes the built-in `backup` role, which is granted read access to
    /// `local.oplog.rs` specifically (backups need it), so no extra
    /// privilege is required here.
    pub async fn oplog_window(&self) -> Result<Option<Duration>> {
        self.recovering(true, |client| async move {
            let oplog = client.database("local").collection::<Document>("oplog.rs");
            let first = tokio::time::timeout(
                SHORT_COMMAND_TIMEOUT,
                oplog.find_one(doc! {}).sort(doc! { "$natural": 1 }),
            )
            .await
            .map_err(|_| {
                anyhow::Error::new(TimedOut("reading the oldest oplog entry timed out".into()))
            })?
            .context("reading the oldest oplog entry failed")?;
            let Some(first) = first else {
                return Ok(None);
            };
            let last = tokio::time::timeout(
                SHORT_COMMAND_TIMEOUT,
                oplog.find_one(doc! {}).sort(doc! { "$natural": -1 }),
            )
            .await
            .map_err(|_| {
                anyhow::Error::new(TimedOut("reading the newest oplog entry timed out".into()))
            })?
            .context("reading the newest oplog entry failed")?;
            let Some(last) = last else {
                return Ok(None);
            };
            let (Some(first_ts), Some(last_ts)) = (
                first.get_timestamp("ts").ok(),
                last.get_timestamp("ts").ok(),
            ) else {
                return Ok(None);
            };
            Ok(Some(Duration::from_secs(
                last_ts.time.saturating_sub(first_ts.time) as u64,
            )))
        })
        .await
    }

    /// How full this node's oplog is: its current size over its configured
    /// maximum (`collStats` on `local.oplog.rs`). mongod truncates the oplog
    /// only past that maximum, so until it is close to full no entry has
    /// been dropped and the window is just the oplog's age. `None` when the
    /// server reports no usable sizes.
    pub async fn oplog_fill(&self) -> Result<Option<f64>> {
        let stats = self
            .recovering(true, |client| async move {
                tokio::time::timeout(
                    SHORT_COMMAND_TIMEOUT,
                    client
                        .database("local")
                        .run_command(doc! { "collStats": "oplog.rs" }),
                )
                .await
                .map_err(|_| {
                    anyhow::Error::new(TimedOut("collStats on the oplog timed out".into()))
                })?
                .context("collStats on the oplog failed")
            })
            .await?;
        Ok(oplog_fill_from_stats(&stats))
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
    /// member still carries that set's config in `local.system.replset` — a
    /// later re-conversion would load it, with the OLD membership, the moment
    /// mongod runs with `--replSet` again — and the change-stream pre-images
    /// collection `config.system.preimages`, which every replica set creates.
    /// The documented way back to a clean standalone is to drop the `local`
    /// database; this does that, and drops the pre-images collection with
    /// it: pre-images are unusable without a replica set (no change streams
    /// on a standalone), the set re-creates the collection, and one left
    /// behind makes the next `--replSet` boot after an UNCLEAN standalone
    /// stop segfault in startup recovery (mongod 8.0 startup_recovery.cpp,
    /// `recoverChangeStreamCollections` skips the oplog-less case only for a
    /// standalone; `cleanupPreImagesCollectionAfterUncleanShutdown` then
    /// reads the earliest oplog timestamp through a null oplog pointer once
    /// `local` is gone — and every retry of that boot is unclean again).
    /// Runs only when either leftover exists. Returns whether anything was
    /// dropped.
    ///
    /// The `root` role carries no `dropDatabase` on `local` nor
    /// `dropCollection` on `config` (its dbAdminAnyDatabase excludes `local`
    /// and `config`; the first CI run hit `Unauthorized` here), so the drops
    /// run under a temporary maintenance role: created, granted to this user,
    /// used from a fresh connection, then revoked and dropped again — no
    /// artifact stays behind.
    pub async fn drop_stale_replset_config(&self) -> Result<bool> {
        let count = self
            .recovering(true, |client| async move {
                tokio::time::timeout(
                    SHORT_COMMAND_TIMEOUT,
                    client
                        .database("local")
                        .collection::<Document>("system.replset")
                        .count_documents(doc! {}),
                )
                .await
                .map_err(|_| {
                    anyhow::Error::new(TimedOut("counting local.system.replset timed out".into()))
                })?
                .context("counting local.system.replset failed")
            })
            .await?;
        let has_preimages = !self
            .recovering(true, |client| async move {
                tokio::time::timeout(
                    SHORT_COMMAND_TIMEOUT,
                    client
                        .database("config")
                        .list_collection_names()
                        .filter(doc! { "name": PREIMAGES_COLLECTION }),
                )
                .await
                .map_err(|_| {
                    anyhow::Error::new(TimedOut(
                        "listing the config database's collections timed out".into(),
                    ))
                })?
                .context("listing the config database's collections failed")
            })
            .await?
            .is_empty();
        if count == 0 && !has_preimages {
            return Ok(false);
        }

        const ROLE: &str = "railwayLocalMaintenance";
        let role_ref = doc! { "role": ROLE, "db": "admin" };
        match self
            .admin(
                doc! {
                    "createRole": ROLE,
                    "privileges": [
                        {
                            "resource": { "db": "local", "collection": "" },
                            "actions": [ "dropDatabase", "dropCollection" ],
                        },
                        {
                            "resource": { "db": "config", "collection": PREIMAGES_COLLECTION },
                            "actions": [ "dropCollection" ],
                        },
                    ],
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
        let mut dropped = Ok(());
        if count > 0 {
            dropped = tokio::time::timeout(RECONFIG_TIMEOUT, fresh.database("local").drop())
                .await
                .map_err(|_| anyhow!("dropping the local database timed out"))
                .and_then(|r| r.context("dropping the local database failed"));
        }
        if dropped.is_ok() && has_preimages {
            dropped = tokio::time::timeout(
                RECONFIG_TIMEOUT,
                fresh
                    .database("config")
                    .collection::<Document>(PREIMAGES_COLLECTION)
                    .drop(),
            )
            .await
            .map_err(|_| anyhow!("dropping config.system.preimages timed out"))
            .and_then(|r| match r {
                Ok(()) => Ok(()),
                // 26 NamespaceNotFound: gone between the listing and the drop.
                Err(e) if matches!(e.kind.as_ref(), ErrorKind::Command(c) if c.code == 26) => {
                    Ok(())
                }
                Err(e) => {
                    Err(anyhow::Error::new(e).context("dropping config.system.preimages failed"))
                }
            });
        }
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
            optime_secs: None,
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

    fn driver_error(kind: ErrorKind) -> anyhow::Error {
        anyhow::Error::new(mongodb::error::Error::from(kind)).context("hello failed")
    }

    #[test]
    fn classify_separates_auth_transport_and_verdicts() {
        // Lost session (code 13) and a refused credential (code 18): auth.
        assert_eq!(
            classify(&server_error(
                13,
                "Command replSetGetStatus requires authentication"
            )),
            Failure::Auth
        );
        assert_eq!(
            classify(&server_error(18, "Authentication failed.")),
            Failure::Auth
        );
        // No server answer at all: transport.
        assert_eq!(
            classify(&anyhow::Error::new(TimedOut(
                "replSetGetStatus timed out after 2s".into()
            ))),
            Failure::Transport
        );
        assert_eq!(
            classify(&driver_error(ErrorKind::Io(Arc::new(
                std::io::Error::from(std::io::ErrorKind::ConnectionReset)
            )))),
            Failure::Transport
        );
        // The server answered: the client works.
        assert_eq!(
            classify(&server_error(94, "no replset config has been received")),
            Failure::Verdict
        );
        assert_eq!(
            command_error_code(&server_error(13, "x")),
            Some(codes::UNAUTHORIZED)
        );
    }

    #[test]
    fn an_auth_failure_rebuilds_at_once_then_backs_off_while_rebuilds_do_not_help() {
        let mut p = RecoveryPolicy::new();
        let t0 = Instant::now();
        // First refusal: rebuild immediately (a lost session heals at once).
        assert!(p.on_failure(Failure::Auth, true, t0));
        // Refused again on the rebuilt client: held back, not per request.
        assert!(!p.on_failure(Failure::Auth, true, t0 + Duration::from_secs(1)));
        // `hello` answering proves nothing about the credential.
        p.on_success(false);
        assert!(!p.on_failure(Failure::Auth, true, t0 + Duration::from_secs(2)));
        // Window over: one more rebuild, and the next window is longer.
        assert!(p.on_failure(Failure::Auth, true, t0 + REBUILD_BACKOFF_MIN));
        assert!(!p.on_failure(
            Failure::Auth,
            true,
            t0 + REBUILD_BACKOFF_MIN + REBUILD_BACKOFF_MIN
        ));
        assert!(p.on_failure(
            Failure::Auth,
            true,
            t0 + REBUILD_BACKOFF_MIN + REBUILD_BACKOFF_MIN * 2
        ));
        // An authenticated success resets it: the next refusal rebuilds at once.
        p.on_success(true);
        assert!(p.on_failure(Failure::Auth, true, t0 + Duration::from_secs(1000)));
        assert_eq!(p.backoff, REBUILD_BACKOFF_MIN);
    }

    /// Boot: the wrapper polls `hello` before the root user exists, which
    /// fails authentication and rebuilds. Until the node joins a set its
    /// authenticated commands answer NotYetInitialized — a server verdict,
    /// which proves the credential. The lost session right after initial
    /// sync must then rebuild at once, not wait out the boot rebuild's window.
    #[test]
    fn a_lost_session_after_the_credential_worked_rebuilds_even_with_a_boot_rebuild_armed() {
        let mut p = RecoveryPolicy::new();
        let t0 = Instant::now();
        assert!(p.on_failure(Failure::Auth, false, t0));
        assert!(!p.on_failure(Failure::Verdict, true, t0 + Duration::from_secs(5)));
        assert!(p.on_failure(Failure::Auth, true, t0 + Duration::from_secs(10)));
        // Same with a plain authenticated success in between.
        let mut p = RecoveryPolicy::new();
        assert!(p.on_failure(Failure::Auth, false, t0));
        p.on_success(true);
        assert!(p.on_failure(Failure::Auth, true, t0 + Duration::from_secs(1)));
    }

    /// A verdict on `hello`/`ping` does not prove the credential.
    #[test]
    fn an_unauthenticated_verdict_does_not_clear_an_auth_rebuild() {
        let mut p = RecoveryPolicy::new();
        let t0 = Instant::now();
        assert!(p.on_failure(Failure::Auth, true, t0));
        assert!(!p.on_failure(Failure::Verdict, false, t0 + Duration::from_secs(1)));
        assert!(!p.on_failure(Failure::Auth, true, t0 + Duration::from_secs(2)));
    }

    /// A transport rebuild never holds back an auth rebuild, and vice versa.
    #[test]
    fn rebuild_windows_are_per_failure_kind() {
        let mut p = RecoveryPolicy::new();
        let t0 = Instant::now();
        for _ in 1..TRANSPORT_FAILURES_BEFORE_REBUILD {
            assert!(!p.on_failure(Failure::Transport, true, t0));
        }
        assert!(p.on_failure(Failure::Transport, true, t0));
        assert!(p.on_failure(Failure::Auth, true, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn the_backoff_stops_growing_at_its_cap() {
        let mut p = RecoveryPolicy::new();
        let mut t = Instant::now();
        for _ in 0..20 {
            assert!(p.on_failure(Failure::Auth, true, t));
            t += REBUILD_BACKOFF_MAX;
        }
        assert_eq!(p.backoff, REBUILD_BACKOFF_MAX);
    }

    #[test]
    fn transport_failures_rebuild_only_after_a_run_and_verdicts_never() {
        let mut p = RecoveryPolicy::new();
        let t0 = Instant::now();
        for _ in 1..TRANSPORT_FAILURES_BEFORE_REBUILD {
            assert!(!p.on_failure(Failure::Transport, true, t0));
        }
        assert!(p.on_failure(Failure::Transport, true, t0));
        // A server verdict breaks the run and never rebuilds.
        let mut p = RecoveryPolicy::new();
        for _ in 1..TRANSPORT_FAILURES_BEFORE_REBUILD {
            assert!(!p.on_failure(Failure::Transport, true, t0));
        }
        assert!(!p.on_failure(Failure::Verdict, true, t0));
        assert!(!p.on_failure(Failure::Transport, true, t0));
        // So does any success, authenticated or not.
        let mut p = RecoveryPolicy::new();
        for _ in 1..TRANSPORT_FAILURES_BEFORE_REBUILD {
            assert!(!p.on_failure(Failure::Transport, true, t0));
        }
        p.on_success(false);
        assert!(!p.on_failure(Failure::Transport, true, t0));
    }

    #[test]
    fn only_hello_and_ping_count_as_unauthenticated() {
        assert!(!needs_auth("hello"));
        assert!(!needs_auth("ping"));
        assert!(needs_auth("replSetGetStatus"));
        assert!(needs_auth("replSetGetConfig"));
    }

    #[test]
    fn oplog_fill_reads_size_over_max_in_any_numeric_encoding() {
        assert_eq!(
            oplog_fill_from_stats(&doc! { "size": 50i32, "maxSize": 100i64 }),
            Some(0.5)
        );
        assert_eq!(
            oplog_fill_from_stats(&doc! { "size": 99.0, "maxSize": 100.0 }),
            Some(0.99)
        );
        assert_eq!(oplog_fill_from_stats(&doc! { "size": 1i64 }), None);
        assert_eq!(
            oplog_fill_from_stats(&doc! { "size": 1i64, "maxSize": 0i64 }),
            None
        );
    }

    #[tokio::test]
    async fn a_rebuild_happens_once_per_generation() {
        let m = Mongo::connect_local(27017, "mongo", "pw");
        let (_, g0) = m.pooled().await;
        assert_eq!(g0, 0);
        let err = server_error(13, "requires authentication");
        // Two callers that observed the same failing generation: one
        // rebuild, not two — the second finds the pool already past it.
        m.rebuild(g0, Failure::Auth, &err).await;
        m.rebuild(g0, Failure::Auth, &err).await;
        assert_eq!(m.pooled().await.1, 1);
        // A stale observation after the rebuild is a no-op too.
        m.rebuild(g0, Failure::Auth, &err).await;
        assert_eq!(m.pooled().await.1, 1);
        // A proven password swap is a new generation with the new identity.
        m.swap_password("other").await;
        assert_eq!(m.pooled().await.1, 2);
        assert_eq!(*m.password.read().await, "other");
    }

    #[test]
    fn member_from_doc_reads_optime_seconds_from_the_timestamp_not_the_date() {
        let m = doc! {
            "_id": 1i32,
            "name": "mongo-2:27017",
            "state": 2i32,
            "stateStr": "SECONDARY",
            "health": 1.0,
            "optime": { "ts": Bson::Timestamp(mongodb::bson::Timestamp { time: 1_700_000_000, increment: 3 }) },
        };
        let member = member_from_doc(&m);
        assert_eq!(member.host, "mongo-2:27017");
        assert_eq!(member.state_str, "SECONDARY");
        assert!(member.healthy);
        assert_eq!(member.optime_secs, Some(1_700_000_000));
    }

    #[test]
    fn member_from_doc_reads_a_zero_optime_as_absent() {
        // What mongod reports for a member it cannot reach.
        let m = doc! {
            "_id": 1i32,
            "name": "mongo-2:27017",
            "state": 8i32,
            "stateStr": "(not reachable/healthy)",
            "health": 0.0,
            "optime": { "ts": Bson::Timestamp(mongodb::bson::Timestamp { time: 0, increment: 0 }), "t": -1i64 },
        };
        assert_eq!(member_from_doc(&m).optime_secs, None);
    }

    #[test]
    fn member_from_doc_tolerates_a_missing_optime() {
        // A member just added has no optime yet — must not panic or fall
        // back to a bogus zero that would read as "1970, wildly behind".
        let m = doc! { "_id": 2i32, "name": "mongo-3:27017", "state": 6i32, "stateStr": "UNKNOWN" };
        let member = member_from_doc(&m);
        assert_eq!(member.optime_secs, None);
    }

    /// The `connectionStatus` reply, as mongod shapes it.
    fn connection_status(users: Vec<(&str, &str)>, roles: Vec<(&str, &str)>) -> Document {
        let users: Vec<Bson> = users
            .into_iter()
            .map(|(user, db)| Bson::Document(doc! { "user": user, "db": db }))
            .collect();
        let roles: Vec<Bson> = roles
            .into_iter()
            .map(|(role, db)| Bson::Document(doc! { "role": role, "db": db }))
            .collect();
        doc! {
            "authInfo": { "authenticatedUsers": users, "authenticatedUserRoles": roles },
            "ok": 1,
        }
    }

    #[test]
    fn root_means_the_named_user_authenticated_on_admin_with_the_root_role() {
        let reply = connection_status(vec![("mongo", "admin")], vec![("root", "admin")]);
        assert!(authenticated_as_root(&reply, "mongo"));
        // Extra roles beside root change nothing.
        let reply = connection_status(
            vec![("mongo", "admin")],
            vec![("readWriteAnyDatabase", "admin"), ("root", "admin")],
        );
        assert!(authenticated_as_root(&reply, "mongo"));
    }

    #[test]
    fn an_admin_user_without_the_root_role_is_not_root() {
        let reply = connection_status(
            vec![("reader", "admin")],
            vec![("readAnyDatabase", "admin")],
        );
        assert!(!authenticated_as_root(&reply, "reader"));
        // Even a rich set of roles is not `root`.
        let reply = connection_status(
            vec![("ops", "admin")],
            vec![
                ("userAdminAnyDatabase", "admin"),
                ("dbAdminAnyDatabase", "admin"),
                ("clusterAdmin", "admin"),
            ],
        );
        assert!(!authenticated_as_root(&reply, "ops"));
    }

    #[test]
    fn the_authenticated_account_must_be_the_one_named() {
        // Some other account holding root does not make THIS request root.
        let reply = connection_status(vec![("other", "admin")], vec![("root", "admin")]);
        assert!(!authenticated_as_root(&reply, "mongo"));
        // A `root`-named role on a different database is a different role.
        let reply = connection_status(vec![("mongo", "admin")], vec![("root", "app")]);
        assert!(!authenticated_as_root(&reply, "mongo"));
        // Same username on a different authentication database.
        let reply = connection_status(vec![("mongo", "app")], vec![("root", "admin")]);
        assert!(!authenticated_as_root(&reply, "mongo"));
    }

    #[test]
    fn an_unauthenticated_or_malformed_reply_is_not_root() {
        assert!(!authenticated_as_root(
            &connection_status(vec![], vec![]),
            "mongo"
        ));
        assert!(!authenticated_as_root(&doc! { "ok": 1 }, "mongo"));
        assert!(!authenticated_as_root(
            &doc! { "authInfo": { "authenticatedUsers": "mongo" } },
            "mongo"
        ));
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
