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
| `setup-auth/` | Go program that calls the Zitadel admin SDK to provision the `citius-api` project, the per-RPC permission catalog, and the seed service users. |
| `pat/` | **gitignored** — bootstrap PAT mount target. |
| `certs/` | **gitignored** — mkcert output. |
| `generated-config.json` | **gitignored** — written by `setup-auth`. |
| `citius-zitadel.env` | **gitignored** — sourceable env file consumed by the server and the integration test suite. |

---

## Configurations

`bootstrap.sh` supports both Docker and Podman as the container engine
(`ENGINE=docker` (default) or `ENGINE=podman`). No engine-specific compose
overlay is needed — the same vendored `docker-compose.yml` works unmodified
on both.

**Troubleshooting**:

On macOS, it has been observed that `./bootstrap.sh up` only works when **SELinux is disabled**.
- Run `podman machine ssh -- setenforce 0` before a Zitadel command
- Reset SELinux with `podman machine ssh -- setenforce 1`

### Dev notes and findings

**Traefix error 404**

Traefik (the `proxy` service) discovers `zitadel-api` / `zitadel-login` and
builds routers for `${ZITADEL_DOMAIN}` via its `--providers.docker=true`
provider, which watches a container-engine API socket bind-mounted into the
`proxy` container at `/var/run/docker.sock` (see the `traefik.http.*` labels
on `zitadel-api`/`zitadel-login` in `docker-compose.yml`). If that socket is
missing or points at the wrong thing, Traefik silently discovers nothing —
no routers get created, and every request (including `setup-auth`'s gRPC
calls to Zitadel) hits Traefik's own fallback and gets a plain-text 404, not
an error from Zitadel itself.

Where `/var/run/docker.sock` actually resolves to differs by engine and by
host OS:

| Host OS | Docker | Podman |
|---|---|---|
| **macOS** | `/var/run/docker.sock` is Docker Desktop's real daemon socket on the host. | Podman runs a Linux VM (`podman machine`). The VM image itself ships a compatibility symlink at `/var/run/docker.sock` → `/run/podman/podman.sock` (the real, systemd-managed API socket, live inside the VM). Bind-mount *source* paths in a compose `volumes:` entry are resolved by the engine that actually creates the container — i.e. **inside the VM** — so the literal, unmodified string `/var/run/docker.sock` already resolves correctly there. No overlay needed. |
| **Linux** | `/var/run/docker.sock` is the real dockerd socket. | Podman ships the same `/var/run/docker.sock` compatibility symlink on native Linux installs too, pointing at the real Podman API socket. Same story: no overlay needed. |

Note that the symlink `/var/run/docker.sock` → `/run/podman/podman.sock` with podman on macOS is present when Docker compatibility is enabled (POdman Desktop > Settings > Docker Compatibility). It is unknown whether the symlink is present when docker compatibility is not enabled.

**The fix in practice**
On macOS, podman runs in a VM called `podman-machine-default` and is accessed with the set of commands `podman machine [command]`. By default, SELinux is enabled (ie. "Restrictive") on the VM. It has been observed that the `./bootstrap.sh up` works when SELinux is disabled (`podman machine ssh -- setenforce 0`), with the mount:
```
volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
```
However, when SELinux is enabled, it does not work. A first exploration with Claude could not determine what the root cause is. Also, Zitadel does not claim support for Podman. The Zitadel docs explicitly require Docker Engine 24+ (https://zitadel.com/docs/self-hosting/deploy/compose) for docker-compose.

**Rootless Podman**

Under Docker, not pinning `user:0` in the containers `zitadel-init` and `zitadel-setup` works fine. However, it does not work with rootless Podman and the boostrap fails with `open /zitadel/bootstrap/admin.pat: permission denied`, because the containers are rootless. 


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

