package auth

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	engerr "github.com/agile-crypto/citius-server/internal/errors"
)

// Environment variable names. These are the contract surface between
// bootstrap/zitadel/citius-zitadel.env and the Citius server.
const (
	EnvAuthEnabled      = "AUTH_ENABLED"
	EnvIssuer           = "ZITADEL_ISSUER"
	EnvIntrospectID     = "INTROSPECT_ID"
	EnvIntrospectSecret = "INTROSPECT_SECRET" //nolint:gosec // env var name, not a credential
	EnvInsecure         = "ZITADEL_INSECURE"
	EnvCacheTTLSeconds  = "CACHE_TTL_SECONDS"
	EnvCacheMaxEntries  = "CACHE_MAX_ENTRIES"
	EnvExpectedAudience = "EXPECTED_AUDIENCE"
)

// defaultCacheTTL and defaultCacheMaxEntries are Citius defaults applied
// by LoadFromEnv when the operator does not set CACHE_TTL_SECONDS /
// CACHE_MAX_ENTRIES. The upstream module does not impose its own
// defaults — its zero-value config disables caching entirely — so we set
// these here to make the production behaviour predictable without
// requiring every deployment to specify them.
const (
	defaultCacheTTL        = 30 * time.Second
	defaultCacheMaxEntries = 10_000
)

// Config is the typed env contract. All fields are immutable after
// LoadFromEnv returns.
type Config struct {
	// Enabled gates the entire authn/authz pipeline. When false, Build
	// returns no-op interceptors and AuthorizeKey/AuthorizePolicy
	// short-circuit to nil.
	Enabled bool

	// Issuer is the Zitadel base URL (e.g. https://citius-auth.localhost).
	Issuer string

	// IntrospectClientID and IntrospectSecret are the Zitadel API
	// application credentials used for /oauth/v2/introspect (HTTP Basic).
	IntrospectClientID string
	IntrospectSecret   string

	// Insecure permits plaintext HTTP for the introspection endpoint.
	// Production must leave this false.
	Insecure bool

	// CacheTTL bounds how long an introspection result may be reused.
	// Zero disables caching (introspect every call).
	CacheTTL time.Duration

	// CacheMaxEntries bounds the in-memory introspection cache.
	CacheMaxEntries int

	// ExpectedAudience, when non-empty, requires the introspected token's
	// "aud" claim to contain at least one of the listed values.
	ExpectedAudience []string

	// PublicMethods lists fully-qualified gRPC methods that bypass authn
	// AND authz. Empty by default. Healthz, if added later, would go here.
	PublicMethods []string

	// AllowUnauthenticatedReflection lets gRPC reflection RPCs
	// ("/grpc.reflection.v1.*", "/grpc.reflection.v1alpha.*") bypass
	// authentication and authorization. The default is false: reflection
	// is treated like any other RPC and would be default-denied.
	//
	// Set true only when the operator has explicitly registered the
	// reflection service AND accepts that an unauthenticated peer can
	// enumerate the API surface. Production deployments should leave
	// reflection unregistered entirely and this field false.
	AllowUnauthenticatedReflection bool
}

// LoadFromEnv reads every recognised env var and returns a populated
// Config. It is the only function in this package that calls os.Getenv;
// callers should invoke it once at startup.
//
// When AUTH_ENABLED=true, ZITADEL_ISSUER, INTROSPECT_ID and
// INTROSPECT_SECRET are required — LoadFromEnv refuses to return an
// enabled-but-incomplete Config, failing fast at startup rather than at
// first request.
func LoadFromEnv() (Config, error) {
	cfg := Config{
		Enabled:            os.Getenv(EnvAuthEnabled) == "true",
		Issuer:             os.Getenv(EnvIssuer),
		IntrospectClientID: os.Getenv(EnvIntrospectID),
		IntrospectSecret:   os.Getenv(EnvIntrospectSecret),
		Insecure:           os.Getenv(EnvInsecure) == "true",
		CacheTTL:           defaultCacheTTL,
		CacheMaxEntries:    defaultCacheMaxEntries,
	}

	if v := os.Getenv(EnvCacheTTLSeconds); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, engerr.New(context.Background(), "auth.LoadFromEnv", engerr.CodeInvalidArgument,
				fmt.Sprintf("parse %s=%q: %v", EnvCacheTTLSeconds, v, err))
		}
		if n < 0 {
			return Config{}, engerr.New(context.Background(), "auth.LoadFromEnv", engerr.CodeInvalidArgument,
				fmt.Sprintf("%s must be >= 0, got %d", EnvCacheTTLSeconds, n))
		}
		cfg.CacheTTL = time.Duration(n) * time.Second
	}

	if v := os.Getenv(EnvCacheMaxEntries); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, engerr.New(context.Background(), "auth.LoadFromEnv", engerr.CodeInvalidArgument,
				fmt.Sprintf("parse %s=%q: %v", EnvCacheMaxEntries, v, err))
		}
		if n < 0 {
			return Config{}, engerr.New(context.Background(), "auth.LoadFromEnv", engerr.CodeInvalidArgument,
				fmt.Sprintf("%s must be >= 0, got %d", EnvCacheMaxEntries, n))
		}
		cfg.CacheMaxEntries = n
	}

	if v := os.Getenv(EnvExpectedAudience); v != "" {
		cfg.ExpectedAudience = splitCSV(v)
	}

	if cfg.Enabled {
		if cfg.Issuer == "" || cfg.IntrospectClientID == "" || cfg.IntrospectSecret == "" {
			return Config{}, engerr.New(context.Background(), "auth.LoadFromEnv", engerr.CodeInvalidArgument,
				fmt.Sprintf("%s=true requires %s, %s and %s to be set",
					EnvAuthEnabled, EnvIssuer, EnvIntrospectID, EnvIntrospectSecret))
		}
	}

	return cfg, nil
}

// splitCSV splits a comma-separated list, trimming whitespace and
// dropping empty entries.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
