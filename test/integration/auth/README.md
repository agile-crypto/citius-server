# Citius × Zitadel integration tests

End-to-end suite that exercises the full Zitadel-backed authn + authz
pipeline against a live local stack.

## Build tags

The suite is hidden behind two cumulative build tags:

- `integration` — opts in to slow / external-dependency tests
- `zitadel`    — opts in to tests that require the bootstrap docker stack

Plain `go test ./...` will never compile or run these files.

## Prerequisites

1. `make zitadel-up` (boots the docker stack, seeds project, writes
   `bootstrap/zitadel/citius-zitadel.env` and `bootstrap/zitadel/tokens/*`)
2. `source bootstrap/zitadel/citius-zitadel.env`
3. `caas-server` running with `AUTH_ENABLED=true` and the issued TLS cert
4. `make test-integration-auth`

## Required environment

| Variable                    | Source                                |
|-----------------------------|---------------------------------------|
| `ZITADEL_ISSUER`            | citius-zitadel.env                    |
| `INTROSPECT_ID/SECRET`      | citius-zitadel.env                    |
| `CITIUS_ADDR`               | host:port the test client should dial |
| `CITIUS_TLS_CA`             | path to PEM CA bundle                 |
| `CITIUS_TLS_SERVER_NAME`    | (optional) SNI / cert SAN to verify; defaults to host portion of `CITIUS_ADDR` |
| `SVC_ADMIN_TOKEN_FILE`      | path to file containing access token  |
| `SVC_TESTER_TOKEN_FILE`     | path to file containing access token  |
| `SVC_READONLY_TOKEN_FILE`   | path to file containing access token  |
| `SVC_NOPERM_TOKEN_FILE`     | path to file containing access token  |

## Coverage

| Test                              | Layer exercised                    |
|-----------------------------------|------------------------------------|
| `TestUnauthenticated_NoTokenIsRejected` | interceptor authn gate       |
| `TestNoPermissionIsForbidden`     | per-method permission registry     |
| `TestReadOnlyCannotCreate`        | per-method permission registry     |
| `TestTesterCannotEscapeNamespace` | per-resource glob scoping          |
| `TestAdminCanCreateAndRead`       | happy path — both layers succeed   |
