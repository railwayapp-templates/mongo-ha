ARG HAPROXY_VERSION=3.2

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

RUN cargo build --release -p haproxy-entrypoint

FROM scratch AS rust-builder-local-output
COPY --from=rust-builder /build/target/release/haproxy-entrypoint /haproxy-entrypoint

FROM scratch AS rust-binaries
COPY --from=rust-builder-local-output / /

# ============================================================
# Final stage: HAProxy with Rust entrypoint
# ============================================================
# Debian-based (not -alpine like redis-ha/mysql-ha): mongosh — the shell
# Railway's Database UI SSH tunnel runs inside the edge — ships as a glibc
# build only (no musl/apk package), so it needs a glibc base to run on.
FROM haproxy:${HAPROXY_VERSION}

USER root

# mongosh for Railway's Database UI SSH tunnel, from MongoDB's own apt repo
# (the only distribution channel for it). wget for the HEALTHCHECK below.
# CI content key (see the build workflow's content gate) — busts this layer
# exactly when the repo code, the upstream base, or debian's pending-fix set
# moved, and keeps it byte-cached (stable digest) otherwise.
ARG PKG_REFRESH=none
ARG MONGOSH_REPO_SERIES=8.0
RUN echo "refresh key: ${PKG_REFRESH}" \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg wget bash \
    && . /etc/os-release \
    && curl -fsSL "https://www.mongodb.org/static/pgp/server-${MONGOSH_REPO_SERIES}.asc" \
        | gpg --dearmor -o /usr/share/keyrings/mongodb-server.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/mongodb-server.gpg] https://repo.mongodb.org/apt/debian ${VERSION_CODENAME}/mongodb-org/${MONGOSH_REPO_SERIES} main" \
        > /etc/apt/sources.list.d/mongodb-org.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends mongodb-mongosh \
    && apt-get purge -y gnupg curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rust-binaries --chmod=755 /haproxy-entrypoint /entrypoint

RUN chown -R haproxy:haproxy /usr/local/etc/haproxy

USER haproxy

# 27017 = write port (primary only, v1 has no read port)
# 8404  = stats page
EXPOSE 27017 8404

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8404/stats || exit 1

ENTRYPOINT ["/entrypoint"]
