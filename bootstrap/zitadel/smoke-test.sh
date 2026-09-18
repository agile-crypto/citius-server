#!/usr/bin/env bash
# bootstrap/zitadel/smoke-test.sh — preflight smoke test for the local stack.
#
# Consumes the non-secret citius-stack.json emitted by bootstrap.sh and checks
# that a client could actually connect to the running stack:
#
#   1. citius-stack.json exists and carries the required non-secret fields.
#   2. The TLS CA file referenced by the config exists and is a PEM certificate.
#   3. The Citius gRPC endpoint is TCP-reachable and presents a certificate
#      chain that verifies against that CA (TLS trust resolves).
#   4. The Zitadel issuer's OIDC discovery document is reachable over TLS using
#      the same CA.
#
# It performs NO authenticated RPC and reads NO secrets — it validates that the
# emitted configuration is internally consistent and the endpoints are live, so
# the UI and the Go/Python SDKs have a working target. A full authenticated RPC
# is exercised by the SDK integration suites, not here.
#
# Engine-agnostic: it checks the running endpoints directly (openssl/curl), so it
# behaves identically whether the stack was brought up with docker or podman.
#
# Usage:
#   bootstrap/zitadel/smoke-test.sh [path/to/citius-stack.json]
#
# Exit codes: 0 all checks passed, non-zero on the first failure.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly STACK_CONFIG="${1:-${SCRIPT_DIR}/citius-stack.json}"

pass() { printf '\033[1;32m[ ok ]\033[0m %s\n' "$*"; }
info() { printf '\033[1;34m[info]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

need jq
need openssl

# --- 1. Config presence and required fields ---------------------------------
[[ -f "$STACK_CONFIG" ]] || fail "config not found: ${STACK_CONFIG} (run bootstrap.sh up first)"

endpoint="$(jq -r '.citius_server.endpoint // empty' "$STACK_CONFIG")"
tls_ca="$(jq -r '.citius_server.tls_ca // empty' "$STACK_CONFIG")"
server_name="$(jq -r '.citius_server.tls_server_name // empty' "$STACK_CONFIG")"
issuer="$(jq -r '.zitadel.issuer // empty' "$STACK_CONFIG")"

[[ -n "$endpoint" ]] || fail "citius_server.endpoint is missing in ${STACK_CONFIG}"
[[ -n "$issuer" ]]   || fail "zitadel.issuer is missing in ${STACK_CONFIG}"
pass "config present with endpoint=${endpoint} issuer=${issuer}"

# --- 2. TLS CA file ---------------------------------------------------------
if [[ -n "$tls_ca" ]]; then
  [[ -f "$tls_ca" ]] || fail "tls_ca file not found: ${tls_ca}"
  grep -q "BEGIN CERTIFICATE" "$tls_ca" || fail "tls_ca is not a PEM certificate: ${tls_ca}"
  pass "TLS CA present: ${tls_ca}"
  ca_args=(-CAfile "$tls_ca")
else
  info "no tls_ca in config; relying on the system trust store"
  ca_args=()
fi

# --- 3. gRPC endpoint TLS reachability --------------------------------------
host="${endpoint%%:*}"
port="${endpoint##*:}"
[[ "$host" != "$endpoint" && -n "$port" ]] || fail "endpoint must be host:port, got ${endpoint}"

servername_args=()
[[ -n "$server_name" ]] && servername_args=(-servername "$server_name")

info "checking TLS handshake to ${host}:${port}"
if echo | openssl s_client -connect "${host}:${port}" "${servername_args[@]}" "${ca_args[@]}" \
      -verify_return_error >/dev/null 2>&1; then
  pass "gRPC endpoint TLS verified against the CA"
else
  fail "TLS handshake/verification to ${host}:${port} failed (is citius-server up? does the CA match?)"
fi

# --- 4. Zitadel OIDC discovery ----------------------------------------------
discovery="${issuer%/}/.well-known/openid-configuration"
info "checking OIDC discovery at ${discovery}"
curl_ca=()
[[ -n "$tls_ca" ]] && curl_ca=(--cacert "$tls_ca")
if command -v curl >/dev/null 2>&1; then
  if curl -fsS "${curl_ca[@]}" "$discovery" | jq -e '.issuer' >/dev/null 2>&1; then
    pass "Zitadel OIDC discovery reachable and trusted"
  else
    fail "OIDC discovery ${discovery} unreachable or untrusted (check issuer host/port and CA)"
  fi
else
  info "curl not found; skipping OIDC discovery check"
fi

pass "smoke test passed — the emitted config points at a reachable, trusted stack"
