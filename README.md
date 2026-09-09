# MongoDB High Availability Template for Railway

MongoDB images for Railway's single-click HA template: a MongoDB replica set
(single primary, majority elections) behind an HAProxy edge, following the
same shape as [`redis-ha`](https://github.com/railwayapp-templates/redis-ha),
[`mysql-ha`](https://github.com/railwayapp-templates/mysql-ha) and
[`postgres-ha`](https://github.com/railwayapp-templates/postgres-ha) — a thin
Rust wrapper around the upstream database image handles membership,
process supervision, and health serving; HAProxy routes client traffic based
on what those wrappers report.

## Topology

```
Application
    ↓
MongoDB HA (HAProxy)
    └─ :27017 (write) → current replica set PRIMARY only
    ↓
MongoDB replica set
    ├─ MongoDB-1 (root)      ← initial primary
    ├─ MongoDB-2 (replica)   ← secondary, failover-ready
    └─ MongoDB-3 (replica)   ← secondary, failover-ready
```

- **MongoDB-1** is the root service — the node the template deploys first,
  and the node that initiates the replica set.
- **MongoDB-2** / **MongoDB-3** join the same set as secondaries.
- **MongoDB HA** is the HAProxy edge — the only thing clients should connect
  to. It exposes a single write port, `:27017`, health-checked against each
  node's `/role` endpoint so writes always land on whichever node is
  currently the primary.
- **v1 has no read port.** This template version is scoped to failover for
  the write path; a read-preference port over the secondaries is a future
  addition.

Minimum set size to tolerate a node loss is 3 — identical reasoning to
redis-ha's Sentinel quorum and mysql-ha's Group Replication majority: a
2-node set can't distinguish "the other node died" from "I'm the one
partitioned away."

### Connection strings carry `directConnection=true`

The edge fronts one server at a time. A MongoDB driver pointed at it WITHOUT
`directConnection=true` would read the primary's `hello` reply, learn the
members' private hostnames from it, and start dialing them itself — which
works inside the Railway project and fails through a public TCP proxy. The
template's `MONGO_URL` / `MONGO_PUBLIC_URL` therefore include the option;
keep it if you build a connection string by hand.

## The `/role` / `/health` contract

Every data node runs an HTTP server (the Rust wrapper) on port 8080, and
HAProxy never talks to MongoDB's wire protocol directly to make routing
decisions:

- `GET /health` — liveness. 200 if mongod answers `ping`, 503 otherwise.
- `GET /role` — the routing signal. 200 **only** when this node is the
  replica set PRIMARY **and** its own view of the set has a reachable
  majority; 503 in every other case, including when the node cannot confirm
  its own status.
- `GET /rs/state` — peer exchange (JSON): whether this node holds a set, its
  primary, whether it holds user data. Consumed by peers' initiate guards.
- `POST /rs/keyfile` — the set's keyfile, to a caller that proves the root
  password (JSON `{username, password}`, verified against this node's mongod).
- `POST /switchover` — ask THIS node to become the primary (Railway's
  "Make Leader"). Freezes the other secondaries, steps the current primary
  down with a catch-up window, and answers 200 once this node has won.

HAProxy's write frontend marks a node UP only while its `/role` returns 200,
with `default-server fall 2 rise 2 on-marked-down shutdown-sessions` — the
first failed check switches probing to the fast interval (500ms), so a real
step-down pulls the node out ~500ms later, while a single slow check on a
healthy primary no longer severs every client connection. `shutdown-sessions`
forces every open client connection to reconnect and land on the new primary
once a node is genuinely marked down.

**This is the split-brain fence.** A primary that loses contact with the rest
of the set must answer 503, not 200, ahead of mongod's own step-down. Fail-
closed is the contract: an uncertain answer is a non-primary answer.

## Wrapper responsibilities

The `mongo-wrapper` binary (one per data node):

- **Keyfile.** Derives the internal-authentication keyfile from the shared
  `RS_KEY` (sha256 → base64) and writes it for mongod before spawning it;
  `--keyFile` implies authentication, so the root account the upstream
  entrypoint creates is enforced cluster-wide.
- **Initiate guard.** mongod persists its replica set config and re-forms the
  set by itself on every restart; the one decision it does not make is how a
  node WITHOUT a config becomes a member. The wrapper queries its declared
  peers (`RS_SEEDS`) over `/rs/state` first. Any peer holding a set means
  this node joins it; a node may only `replSetInitiate` a brand-new set when
  every peer answers, none holds a set, and this node wins the tie-break —
  user data first (an adopted standalone volume must beat the fresh replicas
  its data hasn't reached), declared seed order second — and only after that
  verdict holds through a dwell. A peer whose name is authoritatively gone
  (continuous NXDOMAIN for `PEER_GONE_DWELL_SECONDS`) stops being waited on.
- **Self-adding joiners.** A joiner already named in the set's config just
  waits: the primary delivers the config over heartbeats and initial sync
  rebuilds it (a wiped volume rejoining under its old name). Otherwise the
  joiner adds itself through the primary with a safe `replSetReconfig`, so
  scale-up never needs the survivors' `RS_SEEDS` restamped.
- **Membership prune.** On the primary, a member the set cannot reach whose
  name has been NXDOMAIN for the whole dwell is removed from the config, so a
  scale-down shrinks the majority requirement instead of leaving ghosts that
  vote against every future election. Anything short of that proof (a crash,
  a partition, a redeploy window) keeps the member.
- **Demote on shutdown.** On SIGTERM a primary runs `replSetStepDown` with a
  catch-up window before mongod is signaled, so a planned redeploy is a
  handoff, not a detection-timeout failover.
- **Credential pin.** `MONGO_INITDB_ROOT_PASSWORD` only initializes a fresh
  data dir, and `RS_KEY` (the keyfile's source) is stamped as a reference to
  it — so an edit of the variable would otherwise lock the wrapper out of its
  own mongod and, on the next redeploy, hand each member a keyfile the others
  refuse. The wrapper pins the password it PROVED against mongod and the
  keyfile the set runs with on the volume (`.railway-mongo-auth-pin`); a pin
  outranks the environment at boot, the drift is logged and reported, and a
  properly rotated stored user (`db.changeUserPassword`, then the variable)
  is adopted live. A node with no pin that finds a live set adopts that set's
  keyfile from a peer over `POST /rs/keyfile`, which hands it out only
  against a root password the peer verifies on its own mongod.
- **Standalone mode.** Without `RS_SEEDS` (or with `RS_ENABLED=false`, which
  the revert flow sets) mongod runs with no `--replSet`, exactly as the
  upstream image would. A volume that ran as a replica set member (every HA
  boot records it on the volume before mongod spawns; a volume from an older
  image is recognised by the keyfile in its credential pin) first replays its
  oplog: a member's
  collections are not journaled — durability is the journaled oplog plus
  stable checkpoints, replayed on every `--replSet` boot — and a boot without
  `--replSet` performs no replay, so after a crash before the redeploy (or
  with writes past the majority commit point after a clean stop) mongod drops
  every collection created after the last checkpoint as an unknown ident.
  The wrapper runs a loopback-only recovery mongod with
  `recoverFromOplogAsStandalone=true` and `takeUnstableCheckpointOnShutdown=true`,
  stops it cleanly so the replayed state is checkpointed, and only then starts
  the standalone mongod; a recovery mongod that fails for any reason other
  than "no oplog" stops the node (exit 78) with the fix in its log instead of
  booting over the data. A replica set config left in the `local` database by
  a previous HA life is then dropped — the documented way back to a
  standalone — together with the change-stream pre-images collection
  (`config.system.preimages`: unusable without a replica set, re-created by
  the next set, and a `--replSet` boot after an unclean standalone stop
  segfaults in startup recovery when it finds it without an oplog), so a
  later re-conversion starts from a clean initiate.
- **Volume runtime lock.** An exclusive `flock` at the data dir root for the
  supervisor's whole life, so an overlapping redeploy waits for the previous
  container instead of racing it on WiredTiger's own lock.

## Environment contract

Data node (`mongo-wrapper`):

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `MONGO_INITDB_ROOT_USERNAME` / `MONGO_INITDB_ROOT_PASSWORD` | yes | — | Root account (upstream entrypoint creates it on a fresh volume; the wrapper authenticates with it) |
| `RS_SEEDS` | HA mode | — | Comma-separated `host:port` of every member, template order |
| `RS_KEY` | HA mode | — | Shared secret the keyfile is derived from |
| `RS_ENABLED` | no | `true` | Literal `false` boots standalone even with `RS_SEEDS` present |
| `RS_NAME` | no | `rs0` | Replica set name (`--replSet`) |
| `MONGO_PORT` | no | `27017` | Client/replication port |
| `HEALTH_PORT` | no | `8080` | Wrapper HTTP server |
| `RAILWAY_VOLUME_MOUNT_PATH` / `DATA_DIR` | no | `/data/db` | dbpath |
| `BOOTSTRAP_DWELL_SECONDS` | no | `15` | How long an initiate verdict must hold |
| `PEER_GONE_DWELL_SECONDS` | no | `1800` | NXDOMAIN proof length for waiver/prune |
| `DEMOTE_TIMEOUT_MS` | no | `20000` | Bound on the pre-shutdown step-down |

Extra `mongod` flags may be passed as the container command (CMD); the image
defaults to `--setParameter diagnosticDataCollectionEnabled=false`, matching
Railway's standalone template.

Edge (`haproxy`): `MONGO_NODES` (comma-separated `host:port`), `MONGO_PORT`
(default `27017`), `HEALTH_CHECK_PORT` (default `8080`), plus the
`HAPROXY_*` tunables shared with the other HA edges.

## Images

Published to GHCR by [`build-and-push.yml`](.github/workflows/build-and-push.yml):

- `ghcr.io/railwayapp-templates/mongo-ha/mongo:<X.Y>` — one continuously
  rebuilt line per MongoDB `X.Y` series Docker Hub publishes for the
  supported majors (7, 8), discovered every run; a bundled-version guard
  refuses to publish a tag whose base bundles a different series.
- `ghcr.io/railwayapp-templates/mongo-ha/haproxy:3.2` — the edge.

## Testing

- `cargo test` — unit tests (initiate decision, config editing, keyfile,
  HAProxy rendering).
- `./test/e2e.sh` — docker-based end-to-end suite: set formation and
  replication, failover on primary pause, cold restart, switchover, demote
  on SIGTERM, wiped-volume rejoin, standalone-volume conversion, scale-up
  to 5, minority-partition write fence, paused-vs-deleted member pruning,
  revert-and-reconvert after a clean stop and after a SIGKILL (the crash
  variant is the one a boot without the oplog replay fails: the canary's
  collection is dropped as an unknown ident), a root-password edit without
  rotation (pin keeps the set together) plus a proper rotation (pin follows),
  a fresh member joining
  with a drifted RS_KEY, and the RS_KEY boot guard. Runs on every pull
  request.

## Status

Functional: formation, failover, conversion of a standalone volume, scale
up/down, partition fencing, switchover, revert. Scoped out of v1: a read port
over the secondaries; self-heal of a member mongod reports as too stale to
catch up (it stays RECOVERING for an operator); continuous backup / PITR.
