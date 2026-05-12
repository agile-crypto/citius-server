#!/usr/bin/env bash
# bootstrap/zitadel/bootstrap.sh — lifecycle orchestrator for the Citius
# Zitadel stack.
#
# Subcommands:
#   up      Bring the stack up (default). Idempotent.
#   down    Stop containers but preserve data volumes, .env, certs, PAT,
#           generated-config.json and citius-zitadel.env. Safe to follow
#           with `up` for a fast restart against the same instance.
#   reset   Stop containers AND wipe data volumes, PAT, generated config,
#           citius-zitadel.env. Then `up`. Issues a fresh masterkey only
#           if .env is recreated by the operator.
#   nuke    `reset` plus delete .env. The next `up` regenerates every
#           secret. Operator must be sure.
#   certs   (Re)issue mkcert certificate for ${ZITADEL_DOMAIN}.
#   env     Print path to citius-zitadel.env.
#   help    Show this message.
#
# Exit codes: 0 ok, non-zero on failure. Every error is printed to stderr.

set -euo pipefail
umask 077

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ENV_FILE="${SCRIPT_DIR}/.env"
readonly ENV_EXAMPLE="${SCRIPT_DIR}/.env.example"
readonly PAT_DIR="${SCRIPT_DIR}/pat"
readonly CERTS_DIR="${SCRIPT_DIR}/certs"
readonly GENERATED_CONFIG="${SCRIPT_DIR}/generated-config.json"
readonly OUT_ENV="${SCRIPT_DIR}/citius-zitadel.env"
readonly COMPOSE_PROJECT="citius-zitadel"
readonly BASE_COMPOSE="${SCRIPT_DIR}/docker-compose.yml"
readonly PRODLIKE_COMPOSE="${SCRIPT_DIR}/docker-compose.prodlike.yml"

readonly READINESS_TIMEOUT=120  # seconds

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log()  { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[bootstrap]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[bootstrap]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# Load .env into the current shell so subsequent helpers can read variables.
# When called with --optional the absence of .env is not fatal — used by
# `down`/`nuke` so the cleanup path works after a previous `nuke`.
load_env() {
  local optional=0
  [[ "${1:-}" == "--optional" ]] && optional=1
  if [[ ! -f "$ENV_FILE" ]]; then
    (( optional )) && return 0
    die ".env not found. cp .env.example .env and edit."
  fi
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
}

# Generate a cryptographically random 32-character key (alnum).
gen_secret() {
  LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32
}

# If a variable is empty in .env, generate a value and persist it.
# Usage: ensure_env_secret VAR_NAME
ensure_env_secret() {
  local var="$1"
  local current="${!var:-}"
  if [[ -n "$current" ]]; then
    return 0
  fi
  local value
  value="$(gen_secret)"
  log "generating ${var} (32 chars)"
  if grep -q "^${var}=" "$ENV_FILE"; then
    # macOS/Linux portable in-place edit.
    sed -i.bak -E "s|^${var}=.*$|${var}=${value}|" "$ENV_FILE"
    rm -f "${ENV_FILE}.bak"
  else
    printf '\n%s=%s\n' "$var" "$value" >> "$ENV_FILE"
  fi
  chmod 600 "$ENV_FILE"
  export "${var}=${value}"
}

# Resolve the active TLS overlay path based on TLS_MODE.
tls_overlay_path() {
  local mode="${TLS_MODE:-}"
  [[ -n "$mode" ]] || die "TLS_MODE is empty in .env (expected: local-tls or letsencrypt)"
  case "$mode" in
    local-tls)   echo "${SCRIPT_DIR}/docker-compose.mode-local-tls.yml" ;;
    letsencrypt) echo "${SCRIPT_DIR}/docker-compose.mode-letsencrypt.yml" ;;
    *)           die "unknown TLS_MODE: ${mode}" ;;
  esac
}

# Wrap `docker compose` with our project name and the active overlay set.
compose() {
  docker compose \
    --env-file "$ENV_FILE" \
    --project-name "$COMPOSE_PROJECT" \
    -f "$BASE_COMPOSE" \
    -f "$PRODLIKE_COMPOSE" \
    -f "$(tls_overlay_path)" \
    "$@"
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
preflight() {
  log "preflight checks"
  need_cmd docker
  need_cmd jq
  need_cmd curl
  need_cmd go
  docker compose version >/dev/null 2>&1 || die "docker compose v2 plugin required"

  # Refuse to run while the vendor placeholder is still in place.
  if grep -q '^x-citius-vendor-placeholder: true' "$BASE_COMPOSE"; then
    die "${BASE_COMPOSE} is a placeholder. Vendor the upstream compose file (see bootstrap/zitadel/README.md)."
  fi
  if grep -q '^x-citius-vendor-placeholder: true' "$PRODLIKE_COMPOSE"; then
    die "${PRODLIKE_COMPOSE} is a placeholder. Vendor the upstream prodlike overlay."
  fi

  load_env

  [[ "${ZITADEL_VERSION:-}" != "" && "${ZITADEL_VERSION}" != "latest" ]] \
    || die "ZITADEL_VERSION must be set to a pinned tag (not 'latest')"

  if [[ "${TLS_MODE:-local-tls}" == "local-tls" ]]; then
    need_cmd mkcert
  fi

  # Port preflight (best-effort; warn rather than fail if ss is unavailable).
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn | awk '{print $4}' | grep -Eq ':(443|80)$'; then
      warn "port 80 or 443 appears to be in use; the stack may fail to bind"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Cert issuance (mkcert, dev only)
# ---------------------------------------------------------------------------
do_certs() {
  load_env
  [[ "${TLS_MODE:-local-tls}" == "local-tls" ]] || die "certs subcommand only supported when TLS_MODE=local-tls"
  need_cmd mkcert

  mkdir -p "$CERTS_DIR"
  log "issuing mkcert certificate for ${ZITADEL_DOMAIN}"
  ( cd "$CERTS_DIR" && mkcert -cert-file "${ZITADEL_DOMAIN}.crt" -key-file "${ZITADEL_DOMAIN}.key" "${ZITADEL_DOMAIN}" )

  # Emit a Traefik dynamic-config file that points at the issued cert.
  cat > "${CERTS_DIR}/dynamic.yml" <<EOF
tls:
  certificates:
    - certFile: /etc/traefik/certs/${ZITADEL_DOMAIN}.crt
      keyFile:  /etc/traefik/certs/${ZITADEL_DOMAIN}.key
EOF
  log "certs written to ${CERTS_DIR}"
}

# ---------------------------------------------------------------------------
# Readiness wait
# ---------------------------------------------------------------------------
wait_for_setup() {
  log "waiting for zitadel-setup to complete (timeout=${READINESS_TIMEOUT}s)"
  local elapsed=0
  while (( elapsed < READINESS_TIMEOUT )); do
    local state
    state="$(compose ps zitadel-setup --format '{{.State}}' 2>/dev/null || true)"
    if [[ "$state" == "exited" ]]; then
      log "zitadel-setup exited"
      break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  if (( elapsed >= READINESS_TIMEOUT )); then
    warn "zitadel-setup did not exit within ${READINESS_TIMEOUT}s; last 50 log lines:"
    compose logs --tail 50 zitadel-setup >&2 || true
    die "zitadel-setup did not complete within ${READINESS_TIMEOUT}s"
  fi

  [[ -s "${PAT_DIR}/admin.pat" ]] || die "${PAT_DIR}/admin.pat is missing or empty after setup"
  log "admin PAT present"
}

# ---------------------------------------------------------------------------
# setup-sdk invocation
# ---------------------------------------------------------------------------
run_setup_sdk() {
  log "running setup-sdk"
  (
    cd "${SCRIPT_DIR}/setup-sdk"
    ZITADEL_ADMIN_PAT="$(<"${PAT_DIR}/admin.pat")" \
    ZITADEL_DOMAIN="${ZITADEL_DOMAIN}" \
    ZITADEL_PORT="${ZITADEL_EXTERNALPORT:-443}" \
    ZITADEL_INSECURE="${ZITADEL_INSECURE:-false}" \
      go run .
  )
  [[ -f "$GENERATED_CONFIG" ]] || die "setup-sdk did not produce ${GENERATED_CONFIG}"
}

# ---------------------------------------------------------------------------
# Env emission
# ---------------------------------------------------------------------------
emit_env() {
  [[ -f "$GENERATED_CONFIG" ]] || die "${GENERATED_CONFIG} not found"
  log "emitting ${OUT_ENV}"

  local project_id api_id api_secret expected_aud
  project_id="$(jq -r '.project_id' "$GENERATED_CONFIG")"
  api_id="$(jq -r '.api_app.client_id' "$GENERATED_CONFIG")"
  api_secret="$(jq -r '.api_app.client_secret' "$GENERATED_CONFIG")"
  expected_aud="urn:zitadel:iam:org:project:id:${project_id}:aud"

  {
    echo "# Auto-generated by bootstrap/zitadel/bootstrap.sh — DO NOT EDIT."
    echo "# Source with: set -a && source bootstrap/zitadel/citius-zitadel.env && set +a"
    echo
    echo "export AUTH_ENABLED=true"
    echo "export ZITADEL_ISSUER=https://${ZITADEL_DOMAIN}"
    echo "export ZITADEL_INSECURE=${ZITADEL_INSECURE:-false}"
    echo "export INTROSPECT_ID=${api_id}"
    echo "export INTROSPECT_SECRET=${api_secret}"
    echo "export PROJECT_ID=${project_id}"
    echo "export EXPECTED_AUDIENCE=${expected_aud}"
    echo
    echo "# --- Service-user credentials (integration tests / smoke) ---"
    jq -r '
      .users
      | to_entries[]
      | "export "
        + (.key | gsub("-"; "_") | ascii_upcase)
        + "_CLIENT_ID="
        + .value.client_id
        + "\nexport "
        + (.key | gsub("-"; "_") | ascii_upcase)
        + "_CLIENT_SECRET="
        + .value.client_secret
    ' "$GENERATED_CONFIG"
  } > "$OUT_ENV"
  chmod 600 "$OUT_ENV"
}

# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------
cmd_up() {
  preflight

  ensure_env_secret ZITADEL_MASTERKEY
  ensure_env_secret POSTGRES_ADMIN_PASSWORD
  ensure_env_secret POSTGRES_ZITADEL_PASSWORD

  if [[ "${TLS_MODE:-local-tls}" == "local-tls" ]]; then
    if [[ ! -f "${CERTS_DIR}/${ZITADEL_DOMAIN}.crt" ]]; then
      do_certs
    fi
  fi

  mkdir -p "$PAT_DIR"

  log "docker compose up"
  compose up -d --wait

  wait_for_setup
  run_setup_sdk
  emit_env

  log "stack ready: https://${ZITADEL_DOMAIN}"
  log "env file:    ${OUT_ENV}"
}

cmd_down() {
  load_env --optional
  if [[ ! -f "$ENV_FILE" ]]; then
    warn ".env absent; nothing to stop"
    return 0
  fi
  log "docker compose down (volumes preserved)"
  compose down --remove-orphans
}

# cmd_reset stops containers, wipes data volumes and runtime artefacts,
# then brings the stack back up. .env (masterkey + DB passwords) is
# preserved unless the operator deletes it manually or runs `nuke`.
cmd_reset() {
  load_env --optional
  if [[ -f "$ENV_FILE" ]]; then
    log "docker compose down -v (wiping data volumes)"
    compose down -v --remove-orphans
  fi
  rm -rf "$PAT_DIR" "$GENERATED_CONFIG" "$OUT_ENV"
  cmd_up
}

cmd_nuke() {
  load_env --optional
  if [[ -f "$ENV_FILE" ]]; then
    log "docker compose down -v (wiping data volumes)"
    compose down -v --remove-orphans
  fi
  rm -rf "$PAT_DIR" "$GENERATED_CONFIG" "$OUT_ENV"
  rm -f "$ENV_FILE"
  log "wiped .env, data volumes and runtime artefacts"
}

cmd_env() {
  printf '%s\n' "$OUT_ENV"
}

cmd_help() {
  sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

main() {
  # `help` and `env` are read-only; do not bootstrap .env from .env.example
  # for them or we leak operator state on every `--help` invocation.
  case "${1:-up}" in
    help|-h|--help|env) ;;
    *)
      if [[ ! -f "$ENV_FILE" && -f "$ENV_EXAMPLE" ]]; then
        warn ".env not found; copying from .env.example"
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        chmod 600 "$ENV_FILE"
      fi
      ;;
  esac

  case "${1:-up}" in
    up)    cmd_up ;;
    down)  cmd_down ;;
    reset) cmd_reset ;;
    nuke)  cmd_nuke ;;
    certs) do_certs ;;
    env)   cmd_env ;;
    help|-h|--help) cmd_help ;;
    *)     die "unknown subcommand: $1 (try: help)" ;;
  esac
}

main "$@"
