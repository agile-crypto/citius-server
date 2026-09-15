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

---

## Layout

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Vendored upstream base (Traefik + Postgres + Zitadel API + Login UI). **Pinned**. |
| `docker-compose.prodlike.yml` | Vendored upstream init/setup/start split. |
| `docker-compose.mode-local-tls.yml` | Dev overlay — mkcert cert mounted into Traefik. |
| `docker-compose.mode-letsencrypt.yml` | Prod overlay — ACME via Let's Encrypt. |
| `.env.example` | Template; copy to `.env`. |
| `.env` | **gitignored** — runtime config + generated secrets. |
| `bootstrap.sh` | Lifecycle orchestrator (`up` / `down` / `reset` / `nuke` / `certs` / `verify` / `env`). |
| `setup-auth/` | Go program that provisions and verifies the `citius-api` project, permission catalog, Web application, and machine/human users. |
| `pat/` | **gitignored** — bootstrap PAT mount target. |
| `certs/` | **gitignored** — mkcert output. |
| `generated-config.json` | **gitignored** — written by `setup-auth`. |
| `citius-ui-auth.json` | **gitignored** — non-secret issuer, PKCE client, audience, and demo-user configuration for the UI. |
| `citius-zitadel.env` | **gitignored** — sourceable env file consumed by the server and the integration test suite. |

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
