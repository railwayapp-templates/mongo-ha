#!/bin/bash
# Shadows the official image's entrypoint (kept next to this file as
# docker-entrypoint-upstream.sh — see the Dockerfile).
#
# Railway's standalone `mongo` template starts the official image with its
# own start command: `docker-entrypoint.sh mongod --ipv6 --bind_ip ::,0.0.0.0
# --setParameter diagnosticDataCollectionEnabled=false`. A start command
# replaces this image's ENTRYPOINT, so a service moved onto this image while
# keeping that command would run mongod as pid 1 with no wrapper: no health
# server, no volume lock, no featureCompatibilityVersion completion. Routing
# `docker-entrypoint.sh mongod …` into the wrapper keeps every one of those;
# the wrapper spawns the real upstream entrypoint itself (process_manager.rs)
# and merges the command's mongod flags with its own (passthrough.rs).
#
# Anything else (`docker-entrypoint.sh mongosh`, a shell) goes straight to
# upstream, unchanged.
set -e

if [ "${1:-}" = "mongod" ]; then
	shift
	exec mongo-wrapper "$@"
fi

exec docker-entrypoint-upstream.sh "$@"
