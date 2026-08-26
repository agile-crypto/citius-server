# Citius Server

A reference implementation of the [Abstract Cryptographic API](https://github.com/agile-crypto/api) — a
transport-agnostic, provider-agnostic, policy-driven cryptographic service. It
lets applications express cryptographic *intent* ("I need a signing key") and
have a policy resolve the concrete algorithm, so keys can be governed and
migrated centrally (including the move to post-quantum) without changing call
sites.

> [!WARNING]
> **Not ready for production.** This is an early reference implementation under
> active development. It supports only a subset of the API surface, a small set
> of algorithms, and an in-memory backend. Interfaces, wire formats, and
> persistence are all subject to change. See the [Roadmap](#roadmap) for what is
> planned.

## What works today

The server exposes three gRPC services from the API spec:

| Service | Supported operations |
|---|---|
| `KeyManagementService` | `CreateKey`, `ReadKey`, `TransformKey` |
| `CryptoService` | `Sign`, `Verify`, `DigestSign`, `DigestVerify`, `Encrypt`, `Decrypt` |
| `CryptoPolicyService` | `CreateCryptoPolicy`, `ReadCryptoPolicy`, `UpdateCryptoPolicy` |

- **Algorithms:** ECDSA (P-256/P-384/P-521), RSA-PSS and RSA-PKCS#1v1.5
  (2048/3072/4096), Ed25519 (pure and prehashed), and ML-DSA-44/65/87
  (post-quantum), defined per template in the algorithm catalog.
- **Providers:** a pure-Go software provider and an OpenSSL provider (via
  OpenSSL 3.5+, with an optional FIPS-restricted mode) are both registered
  and implement the full sign/verify/encrypt/decrypt surface at the
  provider layer; a loopback provider is available for testing. Sign,
  verify, prehashed sign/verify, and symmetric encrypt/decrypt are exposed
  over gRPC; MAC, key wrapping/derivation/agreement, digest/XOF, and random
  generation exist as provider capabilities but aren't wired to a handler
  yet (see [Roadmap](#roadmap)).
- **Templates & policies** are loaded from a JSON catalog
  (`proto/standard_algorithms.json`).
- **Storage** is in-memory (non-persistent).
- **Auth** (bearer-token authn/authz via [Zitadel]) is optional and off by
  default.

## Quick start

```sh
# Build and run on :50051 with the default algorithm catalog (no auth, no TLS)
make run

# Or run straight from source
make run-dev

# Enable gRPC reflection for grpcurl exploration
GRPC_REFLECTION=1 make run-dev
```

The server binary accepts:

```
-addr             gRPC listen address (default :50051)
-catalog          path to standard_algorithms.json
-tls-cert         TLS certificate (PEM); required when AUTH_ENABLED=true
-tls-key          TLS private key (PEM); required when AUTH_ENABLED=true
-grpc-reflection  register the gRPC reflection service (default off)
```

## Talking to the server

Use the Citius [Go SDK](https://github.com/agile-crypto/citius-go-sdk) as a client. A typical
intent-based flow — create a key by policy, sign by name, then transform the key
to a post-quantum algorithm without touching the call site:

```go
// Create a key by intent — the policy resolves the concrete algorithm.
_, err := kmClient.CreateKey(ctx,
    keymanagement.NewCreateKeyRequest("contract-signing-key", "prod-signing", scope.SignatureStandard))

// Sign by name — no algorithm identifier at the call site.
resp, err := cryptoClient.Sign(ctx,
    crypto.NewSignRequest("contract-signing-key", payload))

// Later: migrate to post-quantum. Existing Sign/Verify call sites are unchanged.
_, err = kmClient.TransformKey(ctx,
    keymanagement.NewTransformKeyRequest("contract-signing-key", scope.SignatureStandard).
        WithSecurityProperties(&common.SecurityProperties{QuantumSafe: true}))
```

See the SDK's [`examples/`](https://github.com/agile-crypto/citius-go-sdk/tree/main/examples) directory for complete,
runnable clients (including TLS and token auth).

## Optional authentication

Bearer-token authn/authz is provided via [Zitadel]. It is disabled by default;
when enabled, TLS is mandatory. A local Zitadel stack can be bootstrapped with
`make zitadel-up`, and `start-server-with-auth.sh` runs the server against it.

Key environment variables (`AUTH_ENABLED`, `ZITADEL_ISSUER`,
`INTROSPECT_ID`, `INTROSPECT_SECRET`, `EXPECTED_AUDIENCE`, …) are read at
startup — see `internal/auth/config.go`.

## Development

```sh
make build       # compile all packages
make test        # unit tests
make test-race   # unit tests with the race detector
make lint        # golangci-lint + buf lint
make proto       # regenerate Go code from proto definitions
make help        # list all targets
```

## Roadmap

This implementation is actively evolving toward broader coverage of the API
spec. Planned work, roughly in scope order:

- **Functions:** expose MAC, key agreement, encapsulation/decapsulation, key
  wrapping/derivation, digest/XOF, random generation, rotation, migration,
  and the discovery service over gRPC.
- **Algorithms:** expand coverage within each primitive.
- **Provider backends:** additional backends and capabilities — PKCS#11,
  KMS, JCA.
- **Knowledge base:** richer templates and their security properties.
- **gRPC Gateway** for REST/HTTP access.
- **Persistent storage** with encryption at rest.
- **Hierarchical policy** with regulatory profiles.
- **Deployment modes:** local library, remote service, and hybrid (centralized
  policy/control-plane for key evolution).
- **Declarative policy** allowing the system to self-manage key evolution.
- **Packaging:** Dockerfile and Kubernetes support.

[Zitadel]: https://zitadel.com/
</content>
</invoke>
