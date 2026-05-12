package auth

import (
	"context"

	zauth "github.ibm.com/citius/zitadel-grpc-auth"
)

// AuthorizeKey enforces deny-by-default glob matching of name against
// the caller's urn:citius:allowed_key_patterns and
// urn:citius:deny_key_patterns claims.
//
// Returns nil when auth is disabled (Build was called with Enabled=false,
// or never called — see SetEnabledForTest). Otherwise:
//   - Empty allow-list ⇒ deny (Strict semantics).
//   - Any pattern in deny-list matches name ⇒ deny.
//   - Any pattern in allow-list matches name AND no deny match ⇒ allow.
//
// Handlers should call this immediately after extracting the key name
// from the request, before any storage I/O.
func AuthorizeKey(ctx context.Context, name string) error {
	if !authEnabled.Load() {
		return nil
	}
	c := zauth.ClaimsFromContext(ctx)
	if c == nil {
		return zauth.Forbidden("no claims in context")
	}
	return zauth.AuthorizeGlobPatternStrict(name,
		c.StringSlice(ClaimAllowedKeyPatterns),
		c.StringSlice(ClaimDenyKeyPatterns),
	)
}

// AuthorizePolicy is the policy-name analogue of AuthorizeKey, scoping
// against urn:citius:allowed_policy_patterns / urn:citius:deny_policy_patterns.
func AuthorizePolicy(ctx context.Context, name string) error {
	if !authEnabled.Load() {
		return nil
	}
	c := zauth.ClaimsFromContext(ctx)
	if c == nil {
		return zauth.Forbidden("no claims in context")
	}
	return zauth.AuthorizeGlobPatternStrict(name,
		c.StringSlice(ClaimAllowedPolicyPatterns),
		c.StringSlice(ClaimDenyPolicyPatterns),
	)
}

// SetEnabledForTest toggles the package-level enabled flag. Tests that
// construct claims directly (without going through Build) must call this
// to exercise the deny path. Returns the previous value so tests can
// restore it via t.Cleanup.
func SetEnabledForTest(enabled bool) bool {
	return authEnabled.Swap(enabled)
}

// IsForbidden reports whether err originated from one of the resource-
// scoping helpers (or from any upstream PolicyFunc denial). Handlers
// can use this to decide whether to wrap with engerr.CodePolicyViolation
// (which maps to gRPC PermissionDenied) versus another code.
func IsForbidden(err error) bool {
	return zauth.IsForbidden(err)
}

// IsUnauthenticated reports whether err originated from a missing or
// invalid bearer token. Handlers normally do not see this — the
// interceptor short-circuits before the handler is called — but the
// helper is provided for symmetry and for tests.
func IsUnauthenticated(err error) bool {
	return zauth.IsUnauthenticated(err)
}
