ARG MONGO_VERSION=8.0

# ============================================================
# Rust builder stage (statically linked with musl)
# ============================================================
FROM rust:1.90-alpine AS rust-builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY common ./common
COPY mongo-wrapper ./mongo-wrapper
COPY haproxy ./haproxy

RUN cargo build --release -p mongo-wrapper

FROM scratch AS rust-builder-local-output
COPY --from=rust-builder /build/target/release/mongo-wrapper /mongo-wrapper

FROM scratch AS rust-binaries
COPY --from=rust-builder-local-output / /

# ============================================================
# Final stage: MongoDB with Rust entrypoint
# ============================================================
FROM mongo:${MONGO_VERSION}

USER root

# The official mongo image is Ubuntu-based. wget is needed for the
# HEALTHCHECK below. CI passes its content key here (see the build workflow's
# content gate): the value only changes when the repo code, the upstream
# base, or the base's pending-security-fix set moved, so this layer re-runs
# exactly when there is something to pick up — and stays byte-cached (stable
# digest) otherwise. A superseded series' base never re-mints upstream, so
# the apt upgrade below is the only way OS fixes reach a pinned series.
# mongodb-org* packages are held: the OS upgrade must never move the bundled
# server off the series the tag promises.
ARG PKG_REFRESH=none
RUN echo "refresh key: ${PKG_REFRESH}" \
    && apt-mark hold 'mongodb-org*' >/dev/null 2>&1 || true \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rust-binaries --chmod=755 /mongo-wrapper /usr/local/bin/mongo-wrapper

# Runs as root, mirroring redis-ha/mysql-ha: the upstream entrypoint chowns
# the (runtime-mounted) volume and drops to the `mongodb` user itself before
# exec'ing mongod, so the wrapper only needs root for that hand-off and for
# writing the keyfile the mongodb user then reads.

VOLUME ["/data/db"]

# 27017 = MongoDB client port — also carries replica set traffic
# 8080  = wrapper health server (/health, /role, /rs/state, /switchover)
EXPOSE 27017 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["mongo-wrapper"]

# mongo-wrapper always invokes `docker-entrypoint.sh mongod` itself with its
# own flags and appends CMD's args after them — so CMD here carries only
# EXTRA mongod flags, never the `mongod` token itself. The standalone
# template's start command disables diagnostic data collection; keep that
# default for the cluster image.
CMD ["--setParameter", "diagnosticDataCollectionEnabled=false"]
