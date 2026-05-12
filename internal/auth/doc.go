// Package auth wires the Zitadel-backed authentication and authorization
// interceptors into the Citius gRPC server.
//
// The package is a thin, pure-library layer over
// github.ibm.com/citius/zitadel-grpc-auth. It exposes:
//
//   - Config      — typed env contract (LoadFromEnv reads it once).
//   - Build       — returns gRPC server options + a Closer.
//   - AuthorizeKey, AuthorizePolicy — per-resource glob scoping that
//     handlers call in addition to the per-method permission gate.
//
// Discipline:
//
//   - Env is read in exactly one place: LoadFromEnv. The rest of the
//     package treats Config as immutable input.
//   - When Config.Enabled is false, every interceptor is a no-op and
//     AuthorizeKey/AuthorizePolicy short-circuit to nil. The gRPC
//     server still constructs and serves requests as usual — this is
//     the contract the upstream module already honours; mirroring it
//     keeps local dev, smoke tests, and the existing non-auth
//     integration suite working unchanged.
//   - Default-deny: every RPC registered on the gRPC server must appear
//     in the policy registry returned by policyRegistry. A reflection
//     test asserts this; a missing entry is a build-time test failure,
//     not a runtime hole.
//   - Resource scoping uses Strict glob matching — an empty allow-list
//     denies. Empty deny-list is permissive within the allow-list.
//
// This package is the only place in citius-server that imports the
// zitadel-grpc-auth module. Handlers depend on the small surface
// re-exported here; swapping the IdP later is a single-package change.
package auth
