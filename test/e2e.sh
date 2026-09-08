#!/usr/bin/env bash
# End-to-end tests for the mongo-ha images. Pure docker CLI, one host, no
# compose — same harness style as redis-ha/mysql-ha/postgres-ha. Every
# resource is labeled mongo-ha-e2e=1 and cleaned up on exit.
#
# Usage: ./test/e2e.sh [t_name ...]      (default: all tests)
#   MONGO_VERSION=8.0 ./test/e2e.sh      (default 8.0)
#   KEEP=1 ./test/e2e.sh t_set_forms     (skip cleanup for debugging)

set -u

cd "$(dirname "$0")/.."

MONGO_VERSION="${MONGO_VERSION:-8.0}"
IMAGE="mongo-ha-e2e:${MONGO_VERSION}"
NET="mongo-ha-e2e-net"
LABEL="mongo-ha-e2e=1"
ROOT_USER="mongo"
ROOT_PW="e2e-root-pw"
RS_KEY="e2e-shared-key"
RS_NAME="rs0"
SEEDS="mongo-1:27017,mongo-2:27017,mongo-3:27017"
# The health server's HTTP Basic credential (HEALTH_API_USERNAME defaults to
# `railway`), for the scenario that boots the set with HEALTH_API_PASSWORD.
HEALTH_API_PW="e2e-health-api-pw"
HEALTH_API_AUTH="Authorization: Basic $(printf 'railway:%s' "$HEALTH_API_PW" | base64 | tr -d '\n')"
HEALTH_API_WRONG_AUTH="Authorization: Basic $(printf 'railway:not-the-password' | base64 | tr -d '\n')"

PASS=0
FAIL=0
FAILED_TESTS=()

log()  { printf '\033[1;34m[e2e]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ ok ]\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); FAILED_TESTS+=("$*"); dump_logs_once; }

# On the first failure of a scenario, print the tail of every live e2e
# container's log — the only way a CI run's autopsy can name the wrapper's
# reason (the harness's own lines never can). Once per scenario, bounded, so
# a cascade of `bad` lines cannot flood the job log.
DUMPED_THIS_SCENARIO=0
dump_logs_once() {
  [ "$DUMPED_THIS_SCENARIO" = "1" ] && return
  DUMPED_THIS_SCENARIO=1
  local c
  for c in $(docker ps -a --filter "label=$LABEL" --format '{{.Names}}' 2>/dev/null); do
    # The wrapper's own lines (JSON with "level") plus mongod's replication,
    # election and control components — the auth/connection chatter the
    # health probes generate every few seconds would otherwise fill the tail.
    printf '\033[1;33m[logs]\033[0m ---- %s (wrapper + REPL/ELECTION/CONTROL, last 60) ----\n' "$c"
    docker logs "$c" 2>&1 | grep -E '"level":|"c":"(REPL|ELECTION|CONTROL|STORAGE|-)"' | grep -vE '"id":(20436|6788604|5286306|22943|22944|51800|20883)' | tail -60 | cut -c1-360
    if docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true; then
      printf '\033[1;33m[state]\033[0m %s rs.status: ' "$c"
      docker exec "$c" mongosh --quiet "mongodb://$ROOT_USER:$ROOT_PW@127.0.0.1:27017/admin?directConnection=true" \
        --eval 'try { const s = rs.status(); print(JSON.stringify({set: s.set, myState: s.myState, voting: s.votingMembersCount, members: s.members.map(m => ({n: m.name, st: m.stateStr, h: m.health, votes: m.votes}))})) } catch (e) { print("ERR " + e.message) }' 2>&1 | tail -1 | cut -c1-500
      printf '\033[1;33m[state]\033[0m %s /rs/state: ' "$c"
      docker exec "$c" wget -q -O - "http://127.0.0.1:8080/rs/state" 2>&1 | tail -1 | cut -c1-400; echo
      printf '\033[1;33m[state]\033[0m %s /role: ' "$c"
      docker exec "$c" wget -q -S -O - "http://127.0.0.1:8080/role" 2>&1 | grep -E "HTTP/|^[a-z]" | head -2 | tr '\n' ' '; echo
    fi
  done
}

cleanup() {
  rm -f "${HTTP_TRANSCRIPT:-}"
  [ "${KEEP:-0}" = "1" ] && { log "KEEP=1 — leaving resources up"; return; }
  docker ps -aq --filter "label=$LABEL" | xargs -r docker rm -f >/dev/null 2>&1
  docker volume ls -q --filter "label=$LABEL" | xargs -r docker volume rm >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT

ensure_image() {
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    log "building $IMAGE"
    docker build -t "$IMAGE" -f mongo-wrapper/Dockerfile \
      --build-arg MONGO_VERSION="$MONGO_VERSION" . || { echo "image build failed"; exit 1; }
  fi
}

ensure_network() {
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
}

# start_node <n> [extra docker args...] — boots mongo-N with the same env
# shape the Railway template stamps. NODE_SUFFIX appends to every
# hostname/alias/container name — the deletion scenarios park their nodes
# under the reserved `.invalid` TLD so a removed container's name resolves as
# authoritative NXDOMAIN on any resolver (bare names get environment-dependent
# answers once the container is gone).
start_node() {
  local n="$1"; shift
  local host="mongo-$n${NODE_SUFFIX:-}"
  local seeds="${SEEDS_OVERRIDE:-$SEEDS}"
  docker volume create --label "$LABEL" "mongo-ha-e2e-vol-$n" >/dev/null
  docker run -d --label "$LABEL" --restart unless-stopped \
    --name "$host" --hostname "$host" \
    --network "$NET" --network-alias "$host" \
    -v "mongo-ha-e2e-vol-$n:/data/db" \
    -e MONGO_INITDB_ROOT_USERNAME="$ROOT_USER" \
    -e MONGO_INITDB_ROOT_PASSWORD="$ROOT_PW" \
    -e RS_KEY="$RS_KEY" \
    -e RS_NAME="$RS_NAME" \
    -e RS_SEEDS="$seeds" \
    -e RAILWAY_PRIVATE_DOMAIN="$host" \
    -e RAILWAY_ENVIRONMENT_ID="e2e-env" \
    -e RAILWAY_VOLUME_MOUNT_PATH="/data/db" \
    -e BOOTSTRAP_DWELL_SECONDS=5 \
    "$@" \
    "$IMAGE" >/dev/null
}

start_trio() { start_node 1; start_node 2; start_node 3; }

# A scenario that "reuses the running trio" but finds it unhealthy must start
# over from nothing: re-running start_node against existing container names
# only produces docker name conflicts on top of the original failure.
ensure_trio() { teardown_trio; start_trio; }

# Reaps the trio AND any node the scale-up chain added beside it.
teardown_trio() {
  local s="${NODE_SUFFIX:-}" n
  for n in 1 2 3 4 5; do
    docker rm -f "mongo-$n$s" "mongo-$n" >/dev/null 2>&1
    docker volume rm "mongo-ha-e2e-vol-$n" >/dev/null 2>&1
  done
}

# start_standalone <name> [extra docker args...] — boots a standalone (no
# RS_SEEDS) wrapper node under the given name/hostname, the shape a reverted
# service runs in.
start_standalone() {
  local name="$1"; shift
  docker volume create --label "$LABEL" "mongo-ha-e2e-vol-$name" >/dev/null
  docker run -d --label "$LABEL" --restart unless-stopped \
    --name "$name" --hostname "$name" \
    --network "$NET" --network-alias "$name" \
    -v "mongo-ha-e2e-vol-$name:/data/db" \
    -e MONGO_INITDB_ROOT_USERNAME="$ROOT_USER" \
    -e MONGO_INITDB_ROOT_PASSWORD="$ROOT_PW" \
    -e RAILWAY_PRIVATE_DOMAIN="$name" \
    -e RAILWAY_ENVIRONMENT_ID="e2e-env" \
    -e RAILWAY_VOLUME_MOUNT_PATH="/data/db" \
    "$@" \
    "$IMAGE" >/dev/null
}

# start_upstream_standalone <name> [extra docker args...] — the OFFICIAL mongo
# image, the way Railway's standalone template runs it (custom start command
# with --ipv6 --bind_ip). This is the volume a conversion adopts.
start_upstream_standalone() {
  local name="$1"; shift
  docker volume create --label "$LABEL" "mongo-ha-e2e-vol-$name" >/dev/null
  docker run -d --label "$LABEL" --restart unless-stopped \
    --name "$name" --hostname "$name" \
    --network "$NET" --network-alias "$name" \
    -v "mongo-ha-e2e-vol-$name:/data/db" \
    -e MONGO_INITDB_ROOT_USERNAME="$ROOT_USER" \
    -e MONGO_INITDB_ROOT_PASSWORD="$ROOT_PW" \
    "$@" \
    "mongo:${MONGO_VERSION}" \
    docker-entrypoint.sh mongod --ipv6 --bind_ip ::,0.0.0.0 --setParameter diagnosticDataCollectionEnabled=false >/dev/null
}

# mongo <node> <js> — root mongosh eval against the node's local mongod,
# through a direct connection (never topology discovery: a secondary must
# answer for itself).
mongo() {
  local node="$1"; shift
  docker exec "$node" mongosh --quiet \
    "mongodb://$ROOT_USER:$ROOT_PW@127.0.0.1:27017/admin?directConnection=true&authSource=admin" \
    --eval "$1" 2>/dev/null
}

# mongo_diag <node> <js> — like mongo(), but stderr comes along (for a read
# whose empty answer needs the driver's own reason to be diagnosable).
mongo_diag() {
  local node="$1"; shift
  docker exec "$node" mongosh --quiet \
    "mongodb://$ROOT_USER:$ROOT_PW@127.0.0.1:27017/admin?directConnection=true&authSource=admin" \
    --eval "$1" 2>&1
}

# role_code <from-node> <target-node> — HTTP status class of /role (200|503).
role_code() {
  if docker exec "$1" wget -q -O /dev/null "http://$2:8080/role" 2>/dev/null; then
    echo 200
  else
    echo 503
  fi
}

rs_state_json() {
  docker exec "$1" wget -q -O - "http://$2:8080/rs/state" 2>/dev/null
}

# http_code <from-node> <url> [wget args...] — the HTTP status one request
# got (000 when nothing answered), for the assertions that must tell a 401
# from a 503. The raw `wget -S` transcript is left in the HTTP_TRANSCRIPT file
# for header checks — a file rather than a variable because callers capture
# the code with `$(http_code ...)`, and a variable set inside that subshell
# never reaches them. A POST is `--post-data ''` in the extra args, like
# switchover_code.
HTTP_TRANSCRIPT="${TMPDIR:-/tmp}/mongo-ha-e2e-http.$$"
http_code() {
  local from="$1" url="$2"; shift 2
  docker exec "$from" wget -S -O /dev/null "$@" "$url" > "$HTTP_TRANSCRIPT" 2>&1 || true
  awk '/^  HTTP\/[0-9.]+ [0-9][0-9][0-9]/{code=$2} END{print (code ? code : "000")}' "$HTTP_TRANSCRIPT"
}

# healthy_members <node> — how many members the node's own view reports
# healthy (states PRIMARY or SECONDARY).
healthy_members() {
  mongo "$1" 'try { const s = rs.status(); print(s.members.filter(m => m.state === 1 || m.state === 2).length) } catch (e) { print(0) }' | tr -d '[:space:]'
}

# voting_members <node> — `votingMembersCount`: a member that just joined is
# `newlyAdded` (non-voting) until its initial sync completes and the primary's
# automatic reconfig commits. In that window the set reads fully healthy yet a
# primary loss finds no electable majority ("Not standing for election because
# I cannot see a majority") — exactly what the first CI run hit by pausing the
# primary 1.5s after formation. Readiness therefore means healthy AND voting.
voting_members() {
  mongo "$1" 'try { print(rs.status().votingMembersCount) } catch (e) { print(0) }' | tr -d '[:space:]'
}

has_n_healthy() { [ "$(healthy_members "$1")" = "$2" ] && [ "$(voting_members "$1")" = "$2" ]; }
set_is_fully_online() { has_n_healthy "$1" 3; }

my_state() { mongo "$1" 'try { print(rs.status().myState) } catch (e) { print(-1) }' | tr -d '[:space:]'; }

# wait_until <timeout-s> <description> <command...>
wait_until() {
  local timeout="$1" desc="$2"; shift 2
  local waited=0
  until "$@"; do
    sleep 3
    waited=$((waited+3))
    if [ "$waited" -ge "$timeout" ]; then
      log "TIMEOUT ($timeout s) waiting for: $desc"
      return 1
    fi
  done
}

resources() {
  [ -r /proc/meminfo ] || return 0
  local avail total live
  avail="$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)"
  total="$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo)"
  live="$(docker ps -q --filter "label=$LABEL" | wc -l | tr -d ' ')"
  log "resources: ${avail}/${total} MiB available, $live container(s) up"
}

# any_role_200 <probe> <nodes...> — exit 0 when any listed node's /role
# answers 200.
any_role_200() {
  local probe="$1"; shift
  local n
  for n in "$@"; do
    docker exec "$probe" wget -q -O /dev/null "http://$n:8080/role" 2>/dev/null && return 0
  done
  return 1
}

# current_primary <probe> <nodes...> — prints the node whose /role is 200.
current_primary() {
  local probe="$1"; shift
  local n
  for n in "$@"; do
    if [ "$(role_code "$probe" "$n")" = "200" ]; then
      echo "$n"
      return 0
    fi
  done
  return 1
}

# exactly_one_primary <probe> <nodes...> — the /role fence: exactly one 200.
exactly_one_primary() {
  local probe="$1"; shift
  local n count=0
  for n in "$@"; do
    [ "$(role_code "$probe" "$n")" = "200" ] && count=$((count+1))
  done
  [ "$count" = "1" ]
}

node_logged() { docker logs "$1" 2>&1 | grep -F "$2" >/dev/null; }

# ---------------------------------------------------------------------------

t_set_forms_and_replicates() {
  log "t_set_forms_and_replicates"
  start_trio

  wait_until 300 "3 healthy members" set_is_fully_online mongo-1 || { bad "set never formed"; return; }
  ok "set formed with 3 healthy members"

  # Exactly the seed-order winner (mongo-1) answers /role 200 on a fresh deploy.
  local codes
  codes="$(role_code mongo-2 mongo-1)/$(role_code mongo-2 mongo-2)/$(role_code mongo-2 mongo-3)"
  if [ "$codes" = "200/503/503" ]; then
    ok "/role fence: only the primary answers 200 ($codes)"
  else
    bad "/role fence wrong: $codes (want 200/503/503)"
  fi

  mongo mongo-1 'db.getSiblingDB("t").kv.replaceOne({_id: 1}, {_id: 1, v: "from-primary"}, {upsert: true})' >/dev/null
  wait_until 60 "document replicated to a secondary" \
    bash -c '[ "$(docker exec mongo-3 mongosh --quiet "mongodb://'"$ROOT_USER:$ROOT_PW"'@127.0.0.1:27017/admin?directConnection=true" --eval "db.getSiblingDB(\"t\").kv.findOne({_id: 1}).v" 2>/dev/null)" = "from-primary" ]' \
    || { bad "write did not replicate to mongo-3"; return; }
  ok "write on primary visible on secondary"

  if mongo mongo-2 'db.getSiblingDB("t").kv.insertOne({_id: 99, v: "rogue"})' 2>/dev/null | grep -q acknowledged; then
    bad "secondary accepted a direct write"
  else
    ok "secondary refuses direct writes"
  fi
}

t_failover_on_primary_pause() {
  log "t_failover_on_primary_pause (reuses the running trio)"
  set_is_fully_online mongo-1 || { ensure_trio; wait_until 300 "3 healthy" set_is_fully_online mongo-1 || { bad "no set to fail over"; return; }; }

  docker pause mongo-1 >/dev/null
  log "primary paused; waiting for election"

  wait_until 120 "a new primary among mongo-2/3" any_role_200 mongo-2 mongo-2 mongo-3 \
    || { bad "no new primary elected after pause"; docker unpause mongo-1 >/dev/null; return; }

  local new_primary
  new_primary="$(current_primary mongo-2 mongo-2 mongo-3)"
  ok "new primary elected: $new_primary"

  if mongo "$new_primary" 'db.getSiblingDB("t").kv.replaceOne({_id: 2}, {_id: 2, v: "post-failover"}, {upsert: true})' | grep -q acknowledged; then
    ok "write accepted by new primary"
  else
    bad "new primary refused a write"
  fi

  # Bring the old primary back the way Railway would: the container restarts
  # and mongod rejoins from its persisted config.
  docker unpause mongo-1 >/dev/null
  docker restart mongo-1 >/dev/null
  wait_until 300 "old primary rejoined (3 healthy)" set_is_fully_online mongo-2 \
    || { bad "old primary did not rejoin"; return; }
  ok "old primary rejoined the set"

  wait_until 60 "post-failover document visible on rejoined node" \
    bash -c '[ "$(docker exec mongo-1 mongosh --quiet "mongodb://'"$ROOT_USER:$ROOT_PW"'@127.0.0.1:27017/admin?directConnection=true" --eval "db.getSiblingDB(\"t\").kv.findOne({_id: 2}).v" 2>/dev/null)" = "post-failover" ]' \
    || { bad "rejoined node missing post-failover write"; return; }
  ok "rejoined node caught up"

  if [ "$(role_code mongo-2 mongo-1)" = "503" ]; then
    ok "rejoined ex-primary is a secondary (/role 503)"
  else
    bad "rejoined ex-primary still answers /role 200"
  fi
}

t_cold_restart_preserves_set() {
  log "t_cold_restart_preserves_set (reuses the running trio)"
  set_is_fully_online mongo-2 || { bad "no set to cold-restart"; return; }

  # Own canary, written on the current primary: the scenario must not depend
  # on an earlier one having written anything.
  local primary
  primary="$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)" || { bad "no primary before the cold restart"; return; }
  mongo "$primary" 'db.getSiblingDB("t").kv.replaceOne({_id: 3}, {_id: 3, v: "pre-cold-restart"}, {upsert: true, writeConcern: {w: "majority"}})' | grep -q acknowledged \
    || { bad "pre-cold-restart write was not acknowledged"; return; }

  docker stop -t 60 mongo-1 mongo-2 mongo-3 >/dev/null
  log "all nodes stopped; starting them back up"
  docker start mongo-1 mongo-2 mongo-3 >/dev/null

  wait_until 300 "set reformed after cold restart" set_is_fully_online mongo-1 \
    || { bad "set did not reform after cold restart"; return; }
  ok "set reformed after full outage"

  local v
  v="$(mongo mongo-1 'db.getSiblingDB("t").kv.findOne({_id: 3}).v')"
  if [ "$v" = "pre-cold-restart" ]; then
    ok "data survived the cold restart"
  else
    bad "data lost after cold restart (got: '$v')"
  fi

  wait_until 60 "exactly one primary after cold restart" exactly_one_primary mongo-2 mongo-1 mongo-2 mongo-3 \
    && ok "exactly one primary after cold restart" \
    || bad "expected exactly one /role 200 after cold restart"

  if ! node_logged mongo-1 "initiating a new replica set" || [ "$(docker logs mongo-1 2>&1 | grep -c 'initiating a new replica set')" = "1" ]; then
    ok "no second initiate after the cold restart (mongod re-formed the set from its config)"
  else
    bad "a node initiated a NEW set after the cold restart"
  fi
}

t_conversion_adopts_standalone_volume() {
  log "t_conversion_adopts_standalone_volume (fresh environment)"
  teardown_trio

  # Seed a standalone the way Railway's mongo template runs it: the official
  # image, custom start command, data written before any HA wrapper exists.
  start_upstream_standalone mongo-1
  wait_until 120 "upstream standalone answering" \
    bash -c 'docker exec mongo-1 mongosh --quiet "mongodb://'"$ROOT_USER:$ROOT_PW"'@127.0.0.1:27017/admin" --eval "db.runCommand({ping:1}).ok" 2>/dev/null | grep -q 1' \
    || { bad "upstream standalone never came up"; return; }
  docker exec mongo-1 mongosh --quiet "mongodb://$ROOT_USER:$ROOT_PW@127.0.0.1:27017/admin" \
    --eval 'db.getSiblingDB("app").docs.insertMany([{_id: 1, v: "pre-conversion"}, {_id: 2, v: "keep-me"}])' >/dev/null 2>&1
  docker rm -f mongo-1 >/dev/null

  # Conversion: the root reboots on the wrapper image with RS_SEEDS, keeping
  # its volume; two fresh replicas come up beside it. Start the replicas
  # FIRST so the adopted root is the slow one — the race the data-first
  # tie-break exists for.
  start_node 2; start_node 3
  sleep 5
  docker run -d --label "$LABEL" --restart unless-stopped \
    --name mongo-1 --hostname mongo-1 --network "$NET" --network-alias mongo-1 \
    -v "mongo-ha-e2e-vol-mongo-1:/data/db" \
    -e MONGO_INITDB_ROOT_USERNAME="$ROOT_USER" -e MONGO_INITDB_ROOT_PASSWORD="$ROOT_PW" \
    -e RS_KEY="$RS_KEY" -e RS_NAME="$RS_NAME" -e RS_SEEDS="$SEEDS" \
    -e RAILWAY_PRIVATE_DOMAIN=mongo-1 -e RAILWAY_ENVIRONMENT_ID=e2e-env \
    -e RAILWAY_VOLUME_MOUNT_PATH=/data/db -e BOOTSTRAP_DWELL_SECONDS=5 \
    "$IMAGE" >/dev/null

  wait_until 300 "3 healthy members after conversion" set_is_fully_online mongo-1 \
    || { bad "converted set never formed"; return; }
  ok "standalone volume adopted; set formed"

  if [ "$(role_code mongo-2 mongo-1)" = "200" ]; then
    ok "the adopted node initiated (it is the primary)"
  else
    bad "a fresh node became primary over the adopted volume"
  fi

  local v
  v="$(mongo mongo-1 'db.getSiblingDB("app").docs.findOne({_id: 1}).v')"
  [ "$v" = "pre-conversion" ] && ok "pre-conversion data intact on the root" || bad "pre-conversion data missing on root (got '$v')"
  wait_until 120 "pre-conversion data on a replica" \
    bash -c '[ "$(docker exec mongo-3 mongosh --quiet "mongodb://'"$ROOT_USER:$ROOT_PW"'@127.0.0.1:27017/admin?directConnection=true" --eval "db.getSiblingDB(\"app\").docs.findOne({_id: 2}).v" 2>/dev/null)" = "keep-me" ]' \
    && ok "pre-conversion data initial-synced to a replica" \
    || bad "pre-conversion data did not reach mongo-3"

  if mongo mongo-1 'db.getSiblingDB("app").docs.insertOne({_id: 3, v: "post-conversion"})' | grep -q acknowledged; then
    ok "writes accepted after conversion"
  else
    bad "primary refused a write after conversion"
  fi

  # Cleanup for the chain: this scenario's volume for mongo-1 has a
  # different name than start_node's.
  docker rm -f mongo-1 mongo-2 mongo-3 >/dev/null 2>&1
  docker volume rm mongo-ha-e2e-vol-mongo-1 mongo-ha-e2e-vol-2 mongo-ha-e2e-vol-3 >/dev/null 2>&1
}

t_scale_up_to_five() {
  log "t_scale_up_to_five"
  teardown_trio
  start_trio
  wait_until 300 "3 healthy" set_is_fully_online mongo-1 || { bad "no set to scale"; return; }

  # New nodes carry the full membership; the survivors' RS_SEEDS are NOT
  # restamped (the joiner adds itself through the primary).
  SEEDS_OVERRIDE="$SEEDS,mongo-4:27017,mongo-5:27017" start_node 4
  SEEDS_OVERRIDE="$SEEDS,mongo-4:27017,mongo-5:27017" start_node 5

  wait_until 300 "5 healthy members" has_n_healthy mongo-1 5 || { bad "set did not grow to 5"; return; }
  ok "scaled up to 5 members without restamping the survivors"

  if mongo mongo-1 'db.getSiblingDB("t").kv.replaceOne({_id: 5}, {_id: 5, v: "five"}, {upsert: true})' | grep -q acknowledged; then
    ok "primary still writable at 5 members"
  else
    bad "primary refused a write at 5 members"
  fi
  wait_until 60 "exactly one primary at 5 members" exactly_one_primary mongo-2 mongo-1 mongo-2 mongo-3 mongo-4 mongo-5 \
    && ok "exactly one primary at 5 members" || bad "not exactly one primary at 5 members"

  docker rm -f mongo-4 mongo-5 >/dev/null 2>&1
  docker volume rm mongo-ha-e2e-vol-4 mongo-ha-e2e-vol-5 >/dev/null 2>&1
  # The trio keeps two ghosts in its config until the prune dwell passes —
  # t_deleted_member_is_pruned covers that path; here just make sure the
  # remaining 3 keep a majority-capable primary (3 of 5 is a majority).
  wait_until 120 "a primary among the remaining trio" any_role_200 mongo-2 mongo-1 mongo-2 mongo-3 \
    && ok "trio keeps a primary after the scaled-up pair is removed (3 of 5 is still a majority)" \
    || bad "trio lost its primary after the pair was removed"
}

t_minority_partition_write_fence() {
  log "t_minority_partition_write_fence (fresh trio)"
  teardown_trio
  start_trio
  wait_until 300 "3 healthy" set_is_fully_online mongo-1 || { bad "no set to partition"; return; }

  # Isolate the primary from the other two: it must stop answering /role 200
  # and stop accepting writes; the majority side must elect.
  local primary
  primary="$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)"
  docker network disconnect "$NET" "$primary" >/dev/null
  log "$primary isolated from the network"

  local others
  others="$(printf 'mongo-1 mongo-2 mongo-3' | tr ' ' '\n' | grep -v "^$primary$" | tr '\n' ' ')"
  # shellcheck disable=SC2086
  wait_until 120 "majority side elects a new primary" any_role_200 $(echo $others | cut -d' ' -f1) $others \
    || { bad "majority side did not elect"; docker network connect --alias "$primary" "$NET" "$primary"; return; }
  ok "majority side elected a new primary"

  # The isolated node: mongod itself steps down once it loses the majority,
  # and /role must fence it. Probe from inside the isolated container (it has
  # no network but loopback still works).
  wait_until 60 "isolated ex-primary fenced (/role 503 on loopback)" \
    bash -c "! docker exec $primary wget -q -O /dev/null http://127.0.0.1:8080/role 2>/dev/null" \
    && ok "isolated ex-primary answers /role 503" \
    || bad "isolated ex-primary still answers /role 200"

  if mongo "$primary" 'db.getSiblingDB("t").kv.insertOne({_id: 77, v: "split"})' 2>/dev/null | grep -q acknowledged; then
    bad "isolated node accepted a write"
  else
    ok "isolated node refuses writes"
  fi

  docker network connect --alias "$primary" "$NET" "$primary" >/dev/null
  wait_until 300 "partition healed: 3 healthy" set_is_fully_online mongo-2 \
    && ok "ex-primary rejoined after the partition healed" \
    || bad "ex-primary did not rejoin after the partition healed"
  wait_until 60 "exactly one primary after heal" exactly_one_primary mongo-2 mongo-1 mongo-2 mongo-3 \
    && ok "exactly one primary after heal" || bad "not exactly one primary after heal"
}

switchover_code() {
  docker exec "$1" wget -q -O /dev/null --post-data '' "http://$2:8080/switchover" 2>/dev/null && echo 200 || echo 503
}

t_switchover_promotes_requested_node() {
  log "t_switchover_promotes_requested_node (reuses the running trio)"
  set_is_fully_online mongo-1 || { ensure_trio; wait_until 300 "3 healthy" set_is_fully_online mongo-1 || { bad "no set"; return; }; }

  local primary target
  primary="$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)"
  target="$(printf 'mongo-1\nmongo-2\nmongo-3\n' | grep -v "^$primary$" | tail -1)"
  log "primary=$primary target=$target"

  local code
  code="$(switchover_code mongo-2 "$target")"
  if [ "$code" != "200" ]; then
    bad "POST /switchover on $target returned $code"
    return
  fi
  ok "POST /switchover on $target answered 200"

  wait_until 60 "$target answers /role 200" bash -c "[ \"\$(docker exec mongo-2 wget -q -O /dev/null http://$target:8080/role 2>/dev/null && echo 200 || echo 503)\" = 200 ]" \
    && ok "requested node is the primary" || bad "requested node did not become primary"
  wait_until 60 "exactly one primary after switchover" exactly_one_primary mongo-2 mongo-1 mongo-2 mongo-3 \
    && ok "exactly one primary after switchover" || bad "not exactly one primary after switchover"

  # Idempotent on the primary.
  code="$(switchover_code mongo-2 "$target")"
  [ "$code" = "200" ] && ok "switchover on the current primary is a 200 no-op" || bad "switchover on the primary returned $code"
}

# The one mutating route behind HTTP Basic auth: with HEALTH_API_PASSWORD on
# the data nodes, POST /switchover refuses a missing or wrong credential
# (401 + challenge) and honors the right one, while every read and the
# root-password keyfile exchange stay open. Ends by rebuilding the plain trio
# the following scenarios reuse — which is also the compat half of the
# contract: with the variable unset the route is open as before.
t_health_api_auth_gates_switchover() {
  log "t_health_api_auth_gates_switchover (fresh trio with HEALTH_API_PASSWORD)"
  teardown_trio
  start_node 1 -e HEALTH_API_PASSWORD="$HEALTH_API_PW"
  start_node 2 -e HEALTH_API_PASSWORD="$HEALTH_API_PW"
  start_node 3 -e HEALTH_API_PASSWORD="$HEALTH_API_PW"
  wait_until 300 "3 healthy" set_is_fully_online mongo-1 || { bad "no set"; return; }

  local primary target code path
  primary="$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)"
  target="$(printf 'mongo-1\nmongo-2\nmongo-3\n' | grep -v "^$primary$" | tail -1)"
  log "primary=$primary target=$target"

  code="$(http_code mongo-2 "http://$target:8080/switchover" --post-data '')"
  if [ "$code" = 401 ]; then
    ok "unauthenticated POST /switchover answers 401"
    grep -qi 'WWW-Authenticate: Basic realm="railway-ha"' "$HTTP_TRANSCRIPT" \
      && ok "401 carries the Basic challenge" || bad "401 without a WWW-Authenticate: Basic challenge"
  else
    bad "unauthenticated POST /switchover answered $code, want 401"
  fi
  code="$(http_code mongo-2 "http://$target:8080/switchover" --post-data '' --header "$HEALTH_API_WRONG_AUTH")"
  [ "$code" = 401 ] && ok "wrong credential on POST /switchover answers 401" || bad "wrong credential on POST /switchover answered $code, want 401"
  [ "$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)" = "$primary" ] \
    && ok "refused switchovers left the primary in place" || bad "primary moved after refused switchovers"

  for path in /health /role /rs/state; do
    code="$(http_code mongo-2 "http://$primary:8080$path")"
    [ "$code" = 200 ] && ok "GET $path stays open without a credential" || bad "GET $path answered $code without a credential"
  done
  code="$(http_code mongo-2 "http://$primary:8080/rs/keyfile" --header 'Content-Type: application/json' \
    --post-data "{\"username\":\"$ROOT_USER\",\"password\":\"$ROOT_PW\"}")"
  [ "$code" = 200 ] && ok "POST /rs/keyfile still answers the root password without a Basic header" \
    || bad "POST /rs/keyfile with the root password answered $code"

  code="$(http_code mongo-2 "http://$target:8080/switchover" --post-data '' --header "$HEALTH_API_AUTH")"
  [ "$code" = 200 ] && ok "authenticated POST /switchover answers 200" || bad "authenticated POST /switchover answered $code"
  wait_until 60 "$target answers /role 200" bash -c "[ \"\$(docker exec mongo-2 wget -q -O /dev/null http://$target:8080/role 2>/dev/null && echo 200 || echo 503)\" = 200 ]" \
    && ok "requested node is the primary" || bad "requested node did not become primary"
  wait_until 60 "exactly one primary after switchover" exactly_one_primary mongo-2 mongo-1 mongo-2 mongo-3 \
    && ok "exactly one primary after switchover" || bad "not exactly one primary after switchover"

  teardown_trio
  start_trio
  wait_until 300 "3 healthy (no HEALTH_API_PASSWORD)" set_is_fully_online mongo-1 || { bad "no set after the rebuild"; return; }
  primary="$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)"
  target="$(printf 'mongo-1\nmongo-2\nmongo-3\n' | grep -v "^$primary$" | tail -1)"
  code="$(http_code mongo-2 "http://$target:8080/switchover" --post-data '')"
  [ "$code" = 200 ] && ok "without HEALTH_API_PASSWORD, POST /switchover stays open" || bad "without HEALTH_API_PASSWORD, POST /switchover answered $code"
  wait_until 60 "exactly one primary after the open switchover" exactly_one_primary mongo-2 mongo-1 mongo-2 mongo-3 \
    && ok "exactly one primary after the open switchover" || bad "not exactly one primary after the open switchover"
}

t_sigterm_primary_demotes_before_exit() {
  log "t_sigterm_primary_demotes_before_exit (reuses the running trio)"
  set_is_fully_online mongo-1 || { ensure_trio; wait_until 300 "3 healthy" set_is_fully_online mongo-1 || { bad "no set"; return; }; }

  local primary
  primary="$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)"
  # -t 60: docker's default 10s grace would SIGKILL the wrapper mid-step-down
  # (catch-up window 10s + mongod's own shutdown).
  docker stop -t 60 "$primary" >/dev/null
  if node_logged "$primary" "stepping down before shutdown"; then
    ok "primary stepped down on SIGTERM"
  else
    bad "no step-down logged on SIGTERM"
  fi
  local others
  others="$(printf 'mongo-1 mongo-2 mongo-3' | tr ' ' '\n' | grep -v "^$primary$" | tr '\n' ' ')"
  # shellcheck disable=SC2086
  wait_until 60 "a new primary among the survivors" any_role_200 $(echo $others | cut -d' ' -f1) $others \
    && ok "survivors have a primary" || bad "survivors have no primary"
  docker start "$primary" >/dev/null
  wait_until 300 "stopped node rejoined" set_is_fully_online mongo-2 \
    && ok "stopped node rejoined as a member" || bad "stopped node did not rejoin"
}

t_wiped_member_volume_rejoins_fresh() {
  log "t_wiped_member_volume_rejoins_fresh (reuses the running trio)"
  set_is_fully_online mongo-1 || { ensure_trio; wait_until 300 "3 healthy" set_is_fully_online mongo-1 || { bad "no set"; return; }; }

  # A member whose volume is lost comes back under the same name with an
  # empty data dir: it is still in the set's config, so the primary delivers
  # the config over heartbeats and initial sync rebuilds it — no reconfig.
  local primary victim
  primary="$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)" || { bad "no primary before wiping a member"; return; }
  mongo "$primary" 'db.getSiblingDB("t").kv.replaceOne({_id: 4}, {_id: 4, v: "pre-wipe"}, {upsert: true, writeConcern: {w: "majority"}})' | grep -q acknowledged \
    || { bad "pre-wipe write was not acknowledged"; return; }
  victim="$(printf 'mongo-1\nmongo-2\nmongo-3\n' | grep -v "^$primary$" | head -1)"
  local n="${victim#mongo-}"
  docker rm -f "$victim" >/dev/null
  docker volume rm "mongo-ha-e2e-vol-$n" >/dev/null
  start_node "$n"
  wait_until 300 "wiped member back (3 healthy)" set_is_fully_online mongo-1 \
    || { bad "wiped member did not rejoin"; return; }
  ok "wiped member rejoined via initial sync"
  if node_logged "$victim" "already named in the set's config"; then
    ok "wiped member recognized itself in the existing config (no reconfig)"
  else
    bad "wiped member did not take the heartbeat-config path"
  fi
  wait_until 60 "data on the rebuilt member" \
    bash -c "[ \"\$(docker exec $victim mongosh --quiet 'mongodb://$ROOT_USER:$ROOT_PW@127.0.0.1:27017/admin?directConnection=true' --eval 'db.getSiblingDB(\"t\").kv.findOne({_id: 4}).v' 2>/dev/null)\" = pre-wipe ]" \
    && ok "rebuilt member holds the set's data" || bad "rebuilt member is missing data"
}

t_deleted_member_is_pruned() {
  log "t_deleted_member_is_pruned (fresh trio under .invalid, short dwell)"
  teardown_trio
  # Names under the reserved .invalid TLD resolve NXDOMAIN on any resolver
  # once the container is gone — the deletion proof the prune needs.
  NODE_SUFFIX=".invalid" SEEDS_OVERRIDE="mongo-1.invalid:27017,mongo-2.invalid:27017,mongo-3.invalid:27017" \
    start_node 1 -e PEER_GONE_DWELL_SECONDS=20
  NODE_SUFFIX=".invalid" SEEDS_OVERRIDE="mongo-1.invalid:27017,mongo-2.invalid:27017,mongo-3.invalid:27017" \
    start_node 2 -e PEER_GONE_DWELL_SECONDS=20
  NODE_SUFFIX=".invalid" SEEDS_OVERRIDE="mongo-1.invalid:27017,mongo-2.invalid:27017,mongo-3.invalid:27017" \
    start_node 3 -e PEER_GONE_DWELL_SECONDS=20
  wait_until 300 "3 healthy" set_is_fully_online mongo-1.invalid || { bad "no set"; NODE_SUFFIX=".invalid" teardown_trio; return; }

  # Delete a secondary for good (container AND volume).
  local primary victim
  primary="$(current_primary mongo-2.invalid mongo-1.invalid mongo-2.invalid mongo-3.invalid)"
  victim="$(printf 'mongo-1.invalid\nmongo-2.invalid\nmongo-3.invalid\n' | grep -v "^$primary$" | head -1)"
  docker rm -f "$victim" >/dev/null
  docker volume rm "mongo-ha-e2e-vol-${victim#mongo-}" >/dev/null 2>&1
  docker volume rm "mongo-ha-e2e-vol-$(echo "$victim" | sed -E 's/^mongo-([0-9]+).*/\1/')" >/dev/null 2>&1
  log "$victim deleted; waiting for the primary to prune it"

  wait_until 180 "member count drops to 2" \
    bash -c "[ \"\$(docker exec $primary mongosh --quiet 'mongodb://$ROOT_USER:$ROOT_PW@127.0.0.1:27017/admin?directConnection=true' --eval 'rs.conf().members.length' 2>/dev/null | tr -d '[:space:]')\" = 2 ]" \
    && ok "deleted member pruned from the config after the dwell" \
    || bad "deleted member was not pruned"
  if node_logged "$primary" "removed a member whose name has been gone"; then
    ok "prune logged with the NXDOMAIN proof"
  else
    bad "no prune log line"
  fi
  NODE_SUFFIX=".invalid" teardown_trio
}

t_paused_member_is_not_pruned() {
  log "t_paused_member_is_not_pruned (fresh trio, short dwell)"
  teardown_trio
  start_node 1 -e PEER_GONE_DWELL_SECONDS=20
  start_node 2 -e PEER_GONE_DWELL_SECONDS=20
  start_node 3 -e PEER_GONE_DWELL_SECONDS=20
  wait_until 300 "3 healthy" set_is_fully_online mongo-1 || { bad "no set"; return; }

  # A paused container still has its name registered: unreachable, but NOT
  # gone. The primary must keep it in the config however long it stays down.
  local primary victim
  primary="$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)"
  victim="$(printf 'mongo-1\nmongo-2\nmongo-3\n' | grep -v "^$primary$" | head -1)"
  docker pause "$victim" >/dev/null
  sleep 60
  local n
  n="$(mongo "$primary" 'rs.conf().members.length' | tr -d '[:space:]')"
  if [ "$n" = "3" ]; then
    ok "paused (unreachable, not gone) member kept in the config"
  else
    bad "paused member was pruned (members=$n)"
  fi
  docker unpause "$victim" >/dev/null
  wait_until 120 "3 healthy after unpause" set_is_fully_online mongo-1 \
    && ok "paused member rejoined" || bad "paused member did not rejoin"
}

t_revert_to_standalone_and_reconvert() {
  log "t_revert_to_standalone_and_reconvert (fresh trio)"
  teardown_trio
  start_trio
  wait_until 300 "3 healthy" set_is_fully_online mongo-1 || { bad "no set"; return; }
  local primary
  primary="$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)" || { bad "no primary before the revert"; return; }
  mongo "$primary" 'db.getSiblingDB("t").kv.replaceOne({_id: 9}, {_id: 9, v: "before-revert"}, {upsert: true, writeConcern: {w: "majority"}})' | grep -q acknowledged \
    || { bad "pre-revert write was not acknowledged"; return; }
  # The revert keeps the ROOT; make sure it is the primary holding the write
  # (it usually is — a fresh trio's mongo-1 initiates — but never assume).
  if [ "$primary" != "mongo-1" ]; then
    switchover_code mongo-2 mongo-1 >/dev/null
    wait_until 60 "root is primary before the revert" bash -c '[ "$(docker exec mongo-2 wget -q -O /dev/null http://mongo-1:8080/role 2>/dev/null && echo 200 || echo 503)" = 200 ]' \
      || { bad "root could not reclaim primary before the revert"; return; }
  fi

  # Revert: the platform deletes the replicas and strips RS_SEEDS/RS_ENABLED
  # from the root, which reboots standalone on the same image and volume.
  docker rm -f mongo-2 mongo-3 >/dev/null
  docker volume rm mongo-ha-e2e-vol-2 mongo-ha-e2e-vol-3 >/dev/null 2>&1
  docker rm -f mongo-1 >/dev/null
  docker run -d --label "$LABEL" --restart unless-stopped \
    --name mongo-1 --hostname mongo-1 --network "$NET" --network-alias mongo-1 \
    -v "mongo-ha-e2e-vol-1:/data/db" \
    -e MONGO_INITDB_ROOT_USERNAME="$ROOT_USER" -e MONGO_INITDB_ROOT_PASSWORD="$ROOT_PW" \
    -e RAILWAY_PRIVATE_DOMAIN=mongo-1 -e RAILWAY_ENVIRONMENT_ID=e2e-env \
    -e RAILWAY_VOLUME_MOUNT_PATH=/data/db \
    "$IMAGE" >/dev/null

  wait_until 120 "reverted root answers /role 200 standalone" bash -c '[ "$(docker exec mongo-1 wget -q -O /dev/null http://127.0.0.1:8080/role 2>/dev/null && echo 200 || echo 503)" = 200 ]' \
    || { bad "reverted root never became writable"; return; }
  ok "reverted root serves standalone"
  wait_until 60 "stale replica set config dropped" bash -c 'docker logs mongo-1 2>&1 | grep -F "dropped the replica set config" >/dev/null' \
    && ok "stale replica set config dropped on revert" || bad "stale replica set config not dropped"
  [ "$(mongo mongo-1 'db.getSiblingDB("local").system.replset.countDocuments({})' | tr -d '[:space:]')" = "0" ] \
    && ok "local.system.replset is empty on the reverted root" || bad "local.system.replset still holds a config on the reverted root"
  [ "$(mongo mongo-1 'db.getSiblingDB("admin").system.roles.countDocuments({role: "railwayLocalMaintenance"})' | tr -d '[:space:]')" = "0" ] \
    && ok "the maintenance role left no artifact" || bad "the maintenance role was left behind in admin.system.roles"
  local v
  v="$(mongo mongo-1 'db.getSiblingDB("t").kv.findOne({_id: 9}).v')"
  if [ "$v" = "before-revert" ]; then
    ok "data intact after revert"
  else
    log "revert read diagnostics: $(mongo_diag mongo-1 'JSON.stringify({doc: db.getSiblingDB("t").kv.findOne({_id: 9}), count: db.getSiblingDB("t").kv.countDocuments({}), dbs: db.adminCommand({listDatabases: 1, nameOnly: true}).databases.map(d => d.name)})' | tail -3)"
    bad "data lost on revert (got '$v')"
  fi
  if mongo mongo-1 'db.getSiblingDB("t").kv.insertOne({_id: 10, v: "standalone-write"})' | grep -q acknowledged; then
    ok "reverted root accepts writes"
  else
    bad "reverted root refused a write"
  fi

  # Re-convert: RS_SEEDS back on the root, two fresh replicas.
  docker rm -f mongo-1 >/dev/null
  start_node 1; start_node 2; start_node 3
  wait_until 300 "3 healthy after re-conversion" set_is_fully_online mongo-1 \
    || { bad "re-conversion did not form a set"; return; }
  ok "re-converted from the reverted volume"
  [ "$(role_code mongo-2 mongo-1)" = "200" ] && ok "adopted root is the primary again (its data won the initiate tie-break)" || bad "the reverted root is not the primary after re-conversion"
  v="$(mongo mongo-3 'db.getSiblingDB("t").kv.findOne({_id: 10}).v')"
  [ "$v" = "standalone-write" ] && ok "standalone-era write reached a fresh replica" || bad "standalone-era write missing on replica (got '$v')"
}

# restart_node_with_env <n> <extra docker args...> — re-creates mongo-N on its
# EXISTING volume with a different environment (the shape of a variable edit
# followed by a redeploy). Uses the same defaults as start_node, overridden by
# whatever the caller passes (later -e wins in docker run).
restart_node_with_env() {
  local n="$1"; shift
  docker rm -f "mongo-$n" >/dev/null 2>&1
  docker run -d --label "$LABEL" --restart unless-stopped \
    --name "mongo-$n" --hostname "mongo-$n" \
    --network "$NET" --network-alias "mongo-$n" \
    -v "mongo-ha-e2e-vol-$n:/data/db" \
    -e MONGO_INITDB_ROOT_USERNAME="$ROOT_USER" \
    -e MONGO_INITDB_ROOT_PASSWORD="$ROOT_PW" \
    -e RS_KEY="$RS_KEY" \
    -e RS_NAME="$RS_NAME" \
    -e RS_SEEDS="$SEEDS" \
    -e RAILWAY_PRIVATE_DOMAIN="mongo-$n" \
    -e RAILWAY_ENVIRONMENT_ID="e2e-env" \
    -e RAILWAY_VOLUME_MOUNT_PATH="/data/db" \
    -e BOOTSTRAP_DWELL_SECONDS=5 \
    "$@" \
    "$IMAGE" >/dev/null
}

t_password_variable_edit_does_not_rotate() {
  log "t_password_variable_edit_does_not_rotate (fresh trio)"
  teardown_trio
  start_trio
  wait_until 300 "3 healthy" set_is_fully_online mongo-1 || { bad "no set"; return; }
  wait_until 60 "credential pin written on every node" \
    bash -c 'for n in 1 2 3; do docker exec mongo-$n test -s /data/db/.railway-mongo-auth-pin || exit 1; done' \
    || { bad "credential pin never written"; return; }
  ok "credential pin written on every node once the password was proven"
  mongo mongo-1 'db.getSiblingDB("t").kv.replaceOne({_id: 20}, {_id: 20, v: "before-edit"}, {upsert: true})' >/dev/null

  # The edit: MONGO_INITDB_ROOT_PASSWORD (and RS_KEY, which the template
  # derives from it) change in the environment; the stored user does not.
  # Roll every node onto the new environment, secondaries first.
  local primary others n
  primary="$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)"
  others="$(printf 'mongo-1\nmongo-2\nmongo-3\n' | grep -v "^$primary$" | tr '\n' ' ')"
  for n in $others $primary; do
    restart_node_with_env "${n#mongo-}" -e MONGO_INITDB_ROOT_PASSWORD="edited-pw" -e RS_KEY="edited-pw"
    wait_until 300 "$n back in the set" set_is_fully_online "$n" || { bad "$n did not come back after the env edit"; return; }
  done
  ok "every member rejoined after the environment edit (pinned keyfile still shared)"

  # The OLD password is the one mongod enforces — and the one the wrapper uses.
  local v
  v="$(mongo mongo-1 'db.getSiblingDB("t").kv.findOne({_id: 20}).v')"
  [ "$v" = "before-edit" ] && ok "old root password still authenticates; data intact" || bad "old password lost or data missing (got '$v')"
  wait_until 60 "exactly one primary after the roll" exactly_one_primary mongo-2 mongo-1 mongo-2 mongo-3 \
    && ok "/role fence intact after the roll (wrapper still authenticated)" || bad "no single /role 200 after the roll"
  if node_logged mongo-1 "differ from this volume's credential pin"; then
    ok "drift between environment and pin logged at boot"
  else
    bad "no credential-drift warning logged"
  fi
  wait_until 90 "drift verdict logged by the resolver" bash -c 'docker logs mongo-1 2>&1 | grep -F "differs from the password mongod" >/dev/null' \
    && ok "resolver reported the unrotated edit" || bad "resolver never reported the drift"

  # A proper rotation: change the stored user to the environment's value; the
  # resolver adopts it and re-pins, no restart.
  mongo "$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)" 'db.getSiblingDB("admin").changeUserPassword("'"$ROOT_USER"'", "edited-pw")' >/dev/null
  wait_until 120 "resolver adopts the rotated password" \
    bash -c 'for n in 1 2 3; do docker exec mongo-$n grep -q "\"password\":\"edited-pw\"" /data/db/.railway-mongo-auth-pin || exit 1; done' \
    && ok "pin adopted the properly rotated password on every node" || bad "pin did not follow the proper rotation"
  wait_until 60 "exactly one primary after rotation" exactly_one_primary mongo-2 mongo-1 mongo-2 mongo-3 \
    && ok "/role fence intact after the rotation" || bad "fence lost after rotation"
  # Restore the harness password for later scenarios.
  ROOT_PW="edited-pw" mongo "$(current_primary mongo-2 mongo-1 mongo-2 mongo-3)" 'db.getSiblingDB("admin").changeUserPassword("'"$ROOT_USER"'", "e2e-root-pw")' >/dev/null
  teardown_trio
}

t_fresh_member_adopts_live_keyfile() {
  log "t_fresh_member_adopts_live_keyfile (fresh trio)"
  teardown_trio
  start_trio
  wait_until 300 "3 healthy" set_is_fully_online mongo-1 || { bad "no set"; return; }

  # A scale-up node whose RS_KEY does NOT match the set's (the variable was
  # edited after the set formed): it must fetch the live keyfile from a peer
  # (proving the root password) instead of deriving a mismatching one.
  SEEDS_OVERRIDE="$SEEDS,mongo-4:27017" start_node 4 -e RS_KEY="some-other-key"
  wait_until 300 "4 healthy members" has_n_healthy mongo-1 4 \
    && ok "fresh member with a drifted RS_KEY joined the set" || bad "fresh member with a drifted RS_KEY did not join"
  if node_logged mongo-4 "adopted the live set's keyfile from a peer"; then
    ok "joiner adopted the live set's keyfile over /rs/keyfile"
  else
    bad "joiner did not log the keyfile adoption"
  fi
  # And the exchange refuses a wrong password.
  if docker exec mongo-4 wget -q -O /dev/null --header 'Content-Type: application/json' --post-data '{"username":"mongo","password":"wrong"}' http://mongo-1:8080/rs/keyfile 2>/dev/null; then
    bad "/rs/keyfile handed out the keyfile to a wrong password"
  else
    ok "/rs/keyfile refuses a wrong password"
  fi
  docker rm -f mongo-4 >/dev/null 2>&1; docker volume rm mongo-ha-e2e-vol-4 >/dev/null 2>&1
  teardown_trio
}

t_missing_rs_key_refuses_boot() {
  log "t_missing_rs_key_refuses_boot"
  docker rm -f mongo-nokey >/dev/null 2>&1
  docker run -d --label "$LABEL" --name mongo-nokey --network "$NET" \
    -e MONGO_INITDB_ROOT_USERNAME="$ROOT_USER" -e MONGO_INITDB_ROOT_PASSWORD="$ROOT_PW" \
    -e RS_SEEDS="$SEEDS" -e RAILWAY_PRIVATE_DOMAIN=mongo-nokey \
    "$IMAGE" >/dev/null
  wait_until 30 "container exits" bash -c '[ "$(docker inspect -f "{{.State.Running}}" mongo-nokey)" = false ]' \
    || { bad "container without RS_KEY kept running"; docker rm -f mongo-nokey >/dev/null; return; }
  if docker logs mongo-nokey 2>&1 | grep -F "RS_KEY must be set" >/dev/null; then
    ok "HA mode without RS_KEY refuses to boot with a clear error"
  else
    bad "no RS_KEY error in logs"
  fi
  docker rm -f mongo-nokey >/dev/null
}

ALL_TESTS=(
  t_set_forms_and_replicates
  t_failover_on_primary_pause
  t_cold_restart_preserves_set
  t_switchover_promotes_requested_node
  t_health_api_auth_gates_switchover
  t_sigterm_primary_demotes_before_exit
  t_wiped_member_volume_rejoins_fresh
  t_conversion_adopts_standalone_volume
  t_scale_up_to_five
  t_minority_partition_write_fence
  t_paused_member_is_not_pruned
  t_deleted_member_is_pruned
  t_revert_to_standalone_and_reconvert
  t_password_variable_edit_does_not_rotate
  t_fresh_member_adopts_live_keyfile
  t_missing_rs_key_refuses_boot
)

main() {
  ensure_image
  ensure_network

  local tests=("$@")
  [ ${#tests[@]} -eq 0 ] && tests=("${ALL_TESTS[@]}")

  for t in "${tests[@]}"; do
    resources
    DUMPED_THIS_SCENARIO=0
    "$t"
  done

  echo
  log "PASS=$PASS FAIL=$FAIL"
  if [ "$FAIL" -gt 0 ]; then
    for f in "${FAILED_TESTS[@]}"; do log "  failed: $f"; done
  fi
  exit "$FAIL"
}

main "$@"
