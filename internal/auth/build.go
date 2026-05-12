package auth

import (
	zsrv "github.ibm.com/citius/zitadel-grpc-auth/server"
	"google.golang.org/grpc"
)

// Closer releases resources held by the auth bundle (currently the
// introspection cache). Callers should defer Close on shutdown.
type Closer = zsrv.Closer

// Build returns the gRPC server options that install the Citius authn
// + authz interceptor chain, plus a Closer to release any held resources.
//
// When cfg.Enabled is false, Build returns no-op interceptors and a no-op
// Closer — the gRPC server is unaltered, no Zitadel call is made, and no
// claims are attached to the request context. This is the contract that
// keeps AUTH_ENABLED=false a first-class mode for local dev and the
// non-auth integration suite.
func Build(cfg Config) ([]grpc.ServerOption, Closer, error) {
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
