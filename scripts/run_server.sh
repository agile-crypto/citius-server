#!/usr/bin/env bash

## Run from root of server implementation repository
## Requires to have bootstrap/zitadel/citius-zitadel.env set (run make zitadel-up first)

# 1. Build binary
BIN_DIR=bin
SERVER_BIN=$BIN_DIR/caas-server
SERVER_PKG=internal/cmd/server/main

go build -o $SERVER_BIN $SERVER_PKG

# 2. Start server
ZITADEL_DIR=bootstrap/zitadel
ZITADEL_ENV_FILE=$ZITADEL_DIR/citius-zitadel.env
ZITADEL_TLS_CERT=$ZITADEL_DIR/certs/local.crt
ZITADEL_TLS_KEY=$ZITADEL_DIR/certs/local.key
ADDR=:50051
CATALOG=proto/standard_algorithms.json
set -e

if [ ! -f "$ZITADEL_ENV_FILE" ]; then
 	echo "ERROR: missing $ZITADEL_ENV_FILE; run 'make zitadel-up' first" >&2
 	exit 1
fi
if [ ! -f "$ZITADEL_TLS_CERT" ]; then
 	echo "ERROR: missing $ZITADEL_TLS_CERT; run 'make zitadel-up' first" >&2
 	exit 1
fi
if [ ! -f "$ZITADEL_TLS_KEY" ]; then
 	echo "ERROR: missing $ZITADEL_TLS_KEY; run 'make zitadel-up' first" >&2
 	exit 1
fi

if [ ! -f "$CATALOG" ]; then
 	echo "ERROR: missing $CATALOG; add JSON catalog of algorithms" >&2
 	exit 1
fi
# Expect these to be set in the environment, or override with defaults here:
: "${ZITADEL_ENV_FILE:?ZITADEL_ENV_FILE must be set}"
: "${ZITADEL_TLS_CERT:?ZITADEL_TLS_CERT must be set}"
: "${ZITADEL_TLS_KEY:?ZITADEL_TLS_KEY must be set}"
: "${SERVER_BIN:?SERVER_BIN must be set}"
: "${ADDR:?ADDR must be set}"
: "${CATALOG:?CATALOG must be set}"

log=$(mktemp -t caas-server.XXXXXX.log)
echo "INFO: Logs will be saved to temporary file: $log while server is running."
set -a
source $ZITADEL_ENV_FILE
set +a
TLS_CERT_FILE="$(realpath "$ZITADEL_TLS_CERT")" \
TLS_KEY_FILE="$(realpath "$ZITADEL_TLS_KEY")" \
GRPC_REFLECTION=1 \
"$SERVER_BIN" -addr "$ADDR" -catalog "$CATALOG" >"$log" 2>&1 &
pid=$!

trap "kill $pid 2>/dev/null; wait $pid 2>/dev/null; rm -f \"$log\"" EXIT INT TERM

port=$(printf "%s" "$ADDR" | sed "s/.*://")
echo "waiting for caas-server (pid=$pid) on :$port ..."

for i in $(seq 1 50); do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "caas-server died early; log:"
    cat "$log"
    exit 1
  fi
  if (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
    exec 3<&-
    exec 3>&-
    break
  fi
  sleep 0.1
done

if ! (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
  echo "caas-server never listened; log:"
  cat "$log"
  exit 1
fi
exec 3<&-
exec 3>&-

echo "caas-server up; running tests"

wait "$pid"