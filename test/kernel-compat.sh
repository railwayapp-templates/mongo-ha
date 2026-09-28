#!/usr/bin/env bash
# Exercise the published entrypoint and a real mongod with kernel-release
# fixtures. The bind mount changes only the container's procfs view; this
# tests policy selection, NOT execution on a different physical kernel.
set -euo pipefail
IMAGE="${MONGO_HA_E2E_IMAGE:-mongo-ha-e2e:8.0}"
fixtures=$(mktemp -d)
name="mongo-kernel-compat-$$"
cleanup() {
  docker rm -fv "$name" >/dev/null 2>&1 || true
  rm -rf "$fixtures"
}
trap cleanup EXIT

inherited='glibc.malloc.arena_max=2:glibc.pthread.rseq=0'
for release in 6.18.15+deb13-cloud-amd64 6.19.10+deb13-cloud-amd64 7.0.13-generic 7.0.14-generic unknown; do
  expected="$inherited"
  active=0
  case "$release" in
    6.19.*|7.0.13-*) expected='glibc.malloc.arena_max=2:glibc.pthread.rseq=1'; active=1 ;;
  esac
  printf '%s\n' "$release" > "$fixtures/release"
  # SYS_ADMIN is only for a bind mount in this throwaway container's mount
  # namespace; no host /proc, device, network or Docker socket is mounted.
  docker run -d --name "$name" --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
    --mount "type=bind,src=$fixtures/release,dst=/kernel-release,readonly" \
    -e MONGO_INITDB_ROOT_USERNAME=mongo -e MONGO_INITDB_ROOT_PASSWORD=kernel-test-pw \
    -e "GLIBC_TUNABLES=$inherited" --entrypoint sh "$IMAGE" \
    -c 'mount --bind /kernel-release /proc/sys/kernel/osrelease && exec mongo-wrapper --setParameter diagnosticDataCollectionEnabled=false' >/dev/null
  ready=0
  for ((attempt=0; attempt<90; attempt++)); do
    if docker exec "$name" mongosh --quiet -u mongo -p kernel-test-pw --authenticationDatabase admin \
      --eval 'if(db.adminCommand({getCmdLineOpts:1}).parsed.processManagement?.fork) quit(1); const c=db.getSiblingDB("kernel_test").probe; c.updateOne({_id:1},{$set:{value:"preserved"}},{upsert:true}); if(c.findOne({_id:1}).value!=="preserved") quit(1)' >/dev/null 2>&1; then
      ready=1
      break
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then break; fi
    sleep 1
  done
  if [ "$ready" != 1 ]; then
    docker logs --tail 60 "$name" >&2
    echo "FAIL: MongoDB did not accept writes for kernel fixture $release" >&2
    exit 1
  fi
  actual=$(docker exec "$name" sh -c '
    for p in /proc/[0-9]*; do
      if [ "$(cat "$p/comm" 2>/dev/null)" = mongod ]; then
        tr "\000" "\n" < "$p/environ" | grep "^GLIBC_TUNABLES="
        break
      fi
    done')
  if [ "$actual" != "GLIBC_TUNABLES=$expected" ]; then
    echo "FAIL: $release child environment: $actual; expected $expected" >&2
    exit 1
  fi
  logs=$(docker logs "$name" 2>&1)
  count=$(printf '%s' "$logs" | grep -c 'using MongoDB allocator fallback' || true)
  if [ "$count" != "$active" ]; then
    echo "FAIL: $release emitted $count fallback logs, expected $active" >&2
    exit 1
  fi
  echo "PASS: $release — MongoDB write/read, child tunables, one-time log"
  docker rm -fv "$name" >/dev/null
done
