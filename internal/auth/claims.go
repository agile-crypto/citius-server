package auth

// Custom claim keys projected by the Zitadel pre-userinfo action under the
// "urn:citius" namespace. They must match the JavaScript action template
// rendered by zitadel-grpc-auth/admin.RenderActionScript verbatim — the
// integration test suite verifies this against a live token.
const (
	// ClaimNamespace is the URN prefix all custom claims share.
	ClaimNamespace = "urn:citius"

	// ClaimPermissions is the deduplicated list of permission keys
	// (project roles) granted to the calling service user.
	ClaimPermissions = "urn:citius:permissions"

	// ClaimAllowedKeyPatterns / ClaimDenyKeyPatterns scope which keys
	// (by name, with glob matching) the caller may operate on.
	// Empty allowed list = deny all (Strict semantics).
	ClaimAllowedKeyPatterns = "urn:citius:allowed_key_patterns"
	ClaimDenyKeyPatterns    = "urn:citius:deny_key_patterns"

	// ClaimAllowedPolicyPatterns / ClaimDenyPolicyPatterns scope which
	// crypto policies (by name) the caller may reference.
	ClaimAllowedPolicyPatterns = "urn:citius:allowed_policy_patterns"
	ClaimDenyPolicyPatterns    = "urn:citius:deny_policy_patterns"
)
