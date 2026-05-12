# `bootstrap/zitadel/`

> Operator-facing infrastructure that brings up a Citius-owned **Zitadel**
> instance for issuing and introspecting opaque OAuth2 bearer tokens used
> by the Citius gRPC API.

This directory is **not** Go code that ships in the binary. It lives at the
repo root so it can be operated independently of the server build.

---

## Quick start (dev)

```bash
# 1. one-time: trust mkcert's local CA in your OS / browser
mkcert -install

# 2. copy the env template, then bring the stack up
cp bootstrap/zitadel/.env.example bootstrap/zitadel/.env
make zitadel-up         # alias for: cd bootstrap/zitadel && ./bootstrap.sh up
```

On success, `bootstrap/zitadel/citius-zitadel.env` is emitted. Source it
and the Citius server will run with `AUTH_ENABLED=true`:

```bash
set -a && source bootstrap/zitadel/citius-zitadel.env && set +a
make run
```

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
| `bootstrap.sh` | Lifecycle orchestrator (`up` / `down` / `reset` / `nuke` / `certs` / `env`). |
| `setup-sdk/` | Go program that calls the Zitadel admin SDK to provision the `citius-api` project, the per-RPC permission catalog, and the seed service users. |
| `pat/` | **gitignored** — bootstrap PAT mount target. |
| `certs/` | **gitignored** — mkcert output. |
| `generated-config.json` | **gitignored** — written by `setup-sdk`. |
| `citius-zitadel.env` | **gitignored** — sourceable env file consumed by the server and the integration test suite. |

---

## Vendoring upstream compose

The base compose files are placeholders until vendored from a pinned
release tag. To populate them:

```bash
TAG=v3.0.0
curl -fsSL "https://raw.githubusercontent.com/zitadel/zitadel/${TAG}/deploy/compose/docker-compose.yml"          -o bootstrap/zitadel/docker-compose.yml
curl -fsSL "https://raw.githubusercontent.com/zitadel/zitadel/${TAG}/deploy/compose/docker-compose-prodlike.yml" -o bootstrap/zitadel/docker-compose.prodlike.yml
```

Then pin every `image:` line to a digest (`@sha256:...`). `bootstrap.sh`
refuses to run while the placeholder sentinel
(`x-citius-vendor-placeholder: true`) is present.
