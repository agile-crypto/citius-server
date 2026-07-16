package auth

import (
	"sync/atomic"

	zsrv "github.com/agile-crypto/zitadel-grpc-auth/server"
	"google.golang.org/grpc"
)

// Closer releases resources held by the auth bundle (currently the
// introspection cache). Callers should defer Close on shutdown.
type Closer = zsrv.Closer

// authEnabled is set by Build and read by AuthorizeKey / AuthorizePolicy
// to decide whether resource-scoping should run. Storing the bit here
// (rather than inferring it from a missing claim) makes the security
// posture an explicit input to the package, immune to upstream changes
// in how unauthenticated requests are represented in context.
//
// It is an atomic.Bool so Build can be called from a startup goroutine
// and AuthorizeKey can be called from request goroutines without a
// mutex. The expected lifecycle is exactly one Build call per process,
// so the racy case (Build mid-request) is academic.
var authEnabled atomic.Bool

// Build returns the gRPC server options that install the Citius authn
// + authz interceptor chain, plus a Closer to release any held resources.
//
// When cfg.Enabled is false, Build returns no-op interceptors and a no-op
// Closer — the gRPC server is unaltered, no Zitadel call is made, and no
// claims are attached to the request context. This is the contract that
// keeps AUTH_ENABLED=false a first-class mode for local dev and the
// non-auth integration suite.
//
// Build also sets a package-level flag consulted by AuthorizeKey and
// AuthorizePolicy. Callers that bypass Build (tests constructing claims
// directly in context) must call SetEnabledForTest to opt resource-
// scoping in.
func Build(cfg Config) ([]grpc.ServerOption, Closer, error) {
	authEnabled.Store(cfg.Enabled)
	return zsrv.New(zsrv.Config{
		RequireAuth:                    cfg.Enabled,
		Issuer:                         cfg.Issuer,
		IntrospectionClientID:          cfg.IntrospectClientID,
		IntrospectionClientSecret:      cfg.IntrospectSecret,
		Insecure:                       cfg.Insecure,
		CacheTTL:                       cfg.CacheTTL,
		CacheMaxEntries:                cfg.CacheMaxEntries,
		ExpectedIssuer:                 cfg.Issuer,
		ExpectedAudience:               cfg.ExpectedAudience,
		PublicMethods:                  cfg.PublicMethods,
		AllowUnauthenticatedReflection: cfg.AllowUnauthenticatedReflection,
		Policies:                       policyRegistry(),
	})
}
