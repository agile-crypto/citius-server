# `bootstrap/zitadel/`

> Operator-facing infrastructure that brings up a Citius-owned **Zitadel**
> instance for issuing and introspecting opaque OAuth2 bearer tokens used
> by the Citius gRPC API.

This directory is **not** Go code that ships in the binary. It lives at the
repo root so it can be operated independently of the server build.

---

## Prerequisites

### mkcert (dev / `local-tls` mode only)

`mkcert` issues locally-trusted TLS certificates and installs its CA into
the OS / browser trust stores. It is required when `TLS_MODE=local-tls`
(the default for local development).

**Install** (one-time):

```bash
# Linux — download the static binary; no package manager needed.
mkdir -p ~/.local/bin
curl -fsSL "https://dl.filippo.io/mkcert/latest?for=linux/amd64" \
     -o ~/.local/bin/mkcert
chmod +x ~/.local/bin/mkcert
# Make sure ~/.local/bin is on your PATH (it usually is on modern distros).
# If not: echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc

# macOS (Homebrew)
brew install mkcert

# Windows (Chocolatey / Scoop)
choco install mkcert   # or: scoop bucket add extras && scoop install mkcert
```

**Trust the local CA** (one-time, must be re-run after OS reinstall):

```bash
mkcert -install
```

This registers `mkcert`'s root CA in the system trust store and in
Firefox/Chrome. Browsers opened *after* this step will accept the certs
`bootstrap.sh certs` issues.

---

## Quick start (dev)

```bash
# 1. one-time: install mkcert and trust its local CA (see Prerequisites above)
mkcert -install

# 2. copy the env template, then bring the stack up
cp bootstrap/zitadel/.env.example bootstrap/zitadel/.env
make zitadel-up         # alias for: cd bootstrap/zitadel && ./bootstrap.sh up
```

On success, `bootstrap/zitadel/citius-zitadel.env` and the non-secret
`bootstrap/zitadel/citius-ui-auth.json` are emitted. Source the environment
file and the Citius server will run with `AUTH_ENABLED=true`:

```bash
set -a && source bootstrap/zitadel/citius-zitadel.env && set +a
make run
```

Verify the human users, exact grants and resource metadata, claim action, and
Web/PKCE application using read-only Zitadel APIs:

```bash
bootstrap/zitadel/bootstrap.sh verify
```

The command exits non-zero and prints each field that differs from
`bootstrap/zitadel/acl.yaml`.

Exercise the real hosted username/password screen and Authorization Code +
PKCE flow for all three demo personas:

```bash
make zitadel-login-all
```

The command prints one authorization URL at a time. Open it in a browser and
sign in as the named user using the password from `.env`. The callback helper
validates OAuth state, exchanges the code with the PKCE verifier, calls
UserInfo to bind the token to the selected provisioned user ID, and writes the
short-lived token to the gitignored `tokens/` directory without printing it.
Use `make zitadel-login PERSONA=citius-producer` to refresh one token.

With all three tokens present, run the Citius method- and resource-authorization
acceptance matrix:

```bash
make test-integration-auth-human-e2e
```

This starts an authenticated Citius server, confirms each persona's allowed and
denied API categories, and verifies deny precedence for
`demo-restricted-*`. The helper deliberately does not implement a UI session,
refresh, or logout; those remain responsibilities of `citius-ui`.

---

## Unified stack: Zitadel + citius-server in one command

By default `bootstrap.sh up` brings up **only** Zitadel; the Citius server is
then run separately on the host (`make run` after sourcing
`citius-zitadel.env`). Set `CITIUS_SERVER=1` to also build and run the Citius
server **as a container in the same stack**, so one command provisions
everything the UI and the Go/Python SDKs need to run against a real server:

```bash
# Bring up Zitadel AND a containerized citius-server, provision demo users,
# and emit the consolidated non-secret config.
CITIUS_SERVER=1 make zitadel-up
# equivalently: CITIUS_SERVER=1 bootstrap/zitadel/bootstrap.sh up
```

What happens, in order:

1. Zitadel (Traefik + Postgres + API + Login UI) comes up and is provisioned by
   the **existing** `setup-auth` program (OIDC Web app, the CISO/producer/consumer
   demo human users, their permissions, and the `demo-*` resource ACLs). This
   step is unchanged.
2. `citius-zitadel.env` is emitted with the introspection configuration.
3. The **containerized** `citius-server` is built from the repo `Dockerfile` and
   started via `docker-compose.citius.yml`. It joins the stack network, trusts
   the local mkcert CA for token introspection, terminates gRPC TLS with the
   same local certificate, and reads its Zitadel configuration from the
   generated introspection values.
4. `citius-stack.json` is emitted — a single **non-secret** descriptor for
   clients.

### The consolidated config: `citius-stack.json`

Non-secret only. Secrets (introspection client secret, PATs, masterkey, demo
passwords) stay in `citius-zitadel.env`/`generated-config.json`, which remain
mode `0600` and gitignored.

```json
{
  "generated_by": "bootstrap/zitadel/bootstrap.sh",
  "citius_server": {
    "endpoint": "127.0.0.1:50051",
    "tls_enabled": true,
    "tls_ca": "/home/you/.local/share/mkcert/rootCA.pem",
    "tls_server_name": "citius-auth.localhost"
  },
  "zitadel": {
    "issuer": "https://citius-auth.localhost:8443",
    "project_id": "…",
    "oidc_web_app_client_id": "…",
    "audience": "…"
  }
}
```

- The **UI** reads the issuer, OIDC web-app client id, and audience for hosted
  Authorization Code + PKCE login (this is the same data as `citius-ui-auth.json`).
- The **Go SDK** and **Python SDK** read `citius_server.endpoint`, `tls_ca`, and
  `tls_server_name` to make an authenticated RPC over TLS.

### Start and tear-down

| Command | Effect |
|---|---|
| `CITIUS_SERVER=1 bootstrap.sh up` | Idempotent. Brings up Zitadel + citius-server, provisions users, emits config. |
| `CITIUS_SERVER=1 bootstrap.sh down` | Stops containers, **preserves** data volumes and generated config. Fast restart with `up`. |
| `CITIUS_SERVER=1 bootstrap.sh reset` | Stops, **wipes** data volumes and generated artefacts (including `citius-stack.json`), then `up`. |
| `CITIUS_SERVER=1 bootstrap.sh nuke` | `reset` plus deletes `.env` so every secret is regenerated on the next `up`. |

Additional toggles: `CITIUS_SERVER_PUBLISHED_PORT` (host port for gRPC, default
`50051`) and `CITIUS_SERVER_REFLECTION=true` (enable gRPC reflection for
`grpcurl`).

### Using the stack from clients

- **Go SDK by itself:** source `citius-zitadel.env`, mint or reuse a service-user
  token (`tokens/<user>.token`), and dial `CITIUS_ADDR` with `CITIUS_TLS_CA`.
- **Python SDK / UI:** point `CITIUS_OIDC_CONFIG_PATH` at `citius-ui-auth.json`
  and `CITIUS_TLS_CA` at the CA from `citius-stack.json`; the UI forwards a
  hosted-login token to the server per RPC.

> Note on networking: the Zitadel issuer URL (e.g.
> `https://citius-auth.localhost:8443`) is used by both the browser and the
> in-network server. The overlay aliases the domain to the Traefik proxy inside
> the stack network. The exact issuer host/port equivalence between host and
> container is the part most likely to need adjustment on a given machine;
> verify token introspection succeeds after the first `up` and adjust
> `ZITADEL_HTTPS_PORT`/host aliases if the server logs introspection failures.

---

## Layout

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Vendored upstream base (Traefik + Postgres + Zitadel API + Login UI). **Pinned**. |
| `docker-compose.prodlike.yml` | Vendored upstream init/setup/start split. |
| `docker-compose.mode-local-tls.yml` | Dev overlay — mkcert cert mounted into Traefik. |
| `docker-compose.mode-letsencrypt.yml` | Prod overlay — ACME via Let's Encrypt. |
| `docker-compose.citius.yml` | Optional overlay — runs the containerized `citius-server` in the same stack (`CITIUS_SERVER=1`). |
| `.env.example` | Template; copy to `.env`. |
| `.env` | **gitignored** — runtime config + generated secrets. |
| `bootstrap.sh` | Lifecycle orchestrator (`up` / `down` / `reset` / `nuke` / `certs` / `verify` / `login` / `env`). |
| `setup-auth/` | Go program that provisions and verifies the `citius-api` project, permission catalog, Web application, and machine/human users. |
| `interactive-login/` | Operator-run hosted-login/PKCE acceptance helper; tokens are identity-checked and written only to `tokens/`. |
| `pat/` | **gitignored** — bootstrap PAT mount target. |
| `certs/` | **gitignored** — mkcert output. |
| `generated-config.json` | **gitignored** — written by `setup-auth`. |
| `citius-ui-auth.json` | **gitignored** — non-secret issuer, PKCE client, audience, and demo-user configuration for the UI. |
| `citius-zitadel.env` | **gitignored** — sourceable env file consumed by the server and the integration test suite. |
| `citius-stack.json` | **gitignored** — consolidated non-secret descriptor (endpoint, TLS CA, issuer, OIDC client, audience) for the UI and SDKs. |

---

## Vendoring upstream compose

The base + overlay compose files in this directory are placeholders until
vendored from a pinned upstream release. Pick a tag from
<https://github.com/zitadel/zitadel/releases> (v4.x line; the v3 series
is EOL — do not pin to it). At the time of writing, `v4.15.0` is current.

```bash
TAG=v4.15.0
BASE="https://raw.githubusercontent.com/zitadel/zitadel/${TAG}/deploy/compose"

curl -fsSL "${BASE}/docker-compose.yml"                   -o bootstrap/zitadel/docker-compose.yml
curl -fsSL "${BASE}/docker-compose.prodlike.yml"          -o bootstrap/zitadel/docker-compose.prodlike.yml
curl -fsSL "${BASE}/docker-compose.mode-local-tls.yml"    -o bootstrap/zitadel/docker-compose.mode-local-tls.yml
curl -fsSL "${BASE}/docker-compose.mode-letsencrypt.yml"  -o bootstrap/zitadel/docker-compose.mode-letsencrypt.yml
curl -fsSL "${BASE}/traefik-local-tls.yml"                -o bootstrap/zitadel/traefik-local-tls.yml
```

Then:

1. Pin every `image:` line to a digest (`@sha256:...`) — never rely on
   the floating tag for reproducible builds.
2. Reconcile any new env keys upstream introduced into our
   [.env.example](.env.example) (diff against `${BASE}/.env.example`).
3. Remove the `x-citius-vendor-placeholder: true` sentinel from each
   vendored file — `bootstrap.sh` refuses to run while it is present.

> Note: the upstream filename is `docker-compose.prodlike.yml` (a dot
> before `prodlike`, not a hyphen). Earlier revisions of this README had
> the wrong path; the curl above is correct.
