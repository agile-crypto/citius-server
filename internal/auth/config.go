package auth

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variable names. These are the contract surface between
// bootstrap/zitadel/citius-zitadel.env and the Citius server.
const (
	EnvAuthEnabled       = "AUTH_ENABLED"
	EnvIssuer            = "ZITADEL_ISSUER"
	EnvIntrospectID      = "INTROSPECT_ID"
	EnvIntrospectSecret  = "INTROSPECT_SECRET"
	EnvInsecure          = "ZITADEL_INSECURE"
	EnvCacheTTLSeconds   = "CACHE_TTL_SECONDS"
	EnvCacheMaxEntries   = "CACHE_MAX_ENTRIES"
	EnvExpectedAudience  = "EXPECTED_AUDIENCE"
)

// defaultCacheTTL and defaultCacheMaxEntries match the upstream module's
// own defaults; they are repeated here so LoadFromEnv produces a fully
// populated Config that is independent of the upstream zero-value behaviour.
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
			return Config{}, fmt.Errorf("auth: parse %s=%q: %w", EnvCacheTTLSeconds, v, err)
		}
		if n < 0 {
			return Config{}, fmt.Errorf("auth: %s must be >= 0, got %d", EnvCacheTTLSeconds, n)
		}
		cfg.CacheTTL = time.Duration(n) * time.Second
	}

	if v := os.Getenv(EnvCacheMaxEntries); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("auth: parse %s=%q: %w", EnvCacheMaxEntries, v, err)
		}
		if n < 0 {
			return Config{}, fmt.Errorf("auth: %s must be >= 0, got %d", EnvCacheMaxEntries, n)
		}
		cfg.CacheMaxEntries = n
	}

	if v := os.Getenv(EnvExpectedAudience); v != "" {
		cfg.ExpectedAudience = splitCSV(v)
	}

	if cfg.Enabled {
		if cfg.Issuer == "" || cfg.IntrospectClientID == "" || cfg.IntrospectSecret == "" {
			return Config{}, fmt.Errorf(
				"auth: %s=true requires %s, %s and %s to be set",
				EnvAuthEnabled, EnvIssuer, EnvIntrospectID, EnvIntrospectSecret,
			)
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
