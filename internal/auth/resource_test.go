package auth

import (
	"context"
	"testing"

	zauth "github.com/agile-crypto/zitadel-grpc-auth"
	"github.com/stretchr/testify/require"
)

func ctxWith(t *testing.T, allow, deny []string, claimAllow, claimDeny string) context.Context {
	t.Helper()
	raw := map[string]any{"sub": "svc-tester"}
	if allow != nil {
		raw[claimAllow] = toAny(allow)
	}
	if deny != nil {
		raw[claimDeny] = toAny(deny)
	}
	return zauth.ContextWithClaims(context.Background(), zauth.NewClaims(raw))
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func TestAuthorizeKey_DisabledWhenNoClaims(t *testing.T) {
	prev := SetEnabledForTest(false)
	t.Cleanup(func() { SetEnabledForTest(prev) })
	require.NoError(t, AuthorizeKey(context.Background(), "any/key"))
	require.NoError(t, AuthorizePolicy(context.Background(), "any/policy"))
}

func TestAuthorizeKey_EmptyAllowDenies(t *testing.T) {
	prev := SetEnabledForTest(true)
	t.Cleanup(func() { SetEnabledForTest(prev) })
	ctx := ctxWith(t, nil, nil, ClaimAllowedKeyPatterns, ClaimDenyKeyPatterns)
	err := AuthorizeKey(ctx, "tenants/acme/k1")
	require.Error(t, err)
	require.True(t, IsForbidden(err))
}

func TestAuthorizeKey_AllowGlobMatches(t *testing.T) {
	prev := SetEnabledForTest(true)
	t.Cleanup(func() { SetEnabledForTest(prev) })
	ctx := ctxWith(t, []string{"tenants/acme/*"}, nil, ClaimAllowedKeyPatterns, ClaimDenyKeyPatterns)
	require.NoError(t, AuthorizeKey(ctx, "tenants/acme/k1"))
	require.Error(t, AuthorizeKey(ctx, "tenants/other/k1"))
}

func TestAuthorizeKey_DenyOverridesAllow(t *testing.T) {
	prev := SetEnabledForTest(true)
	t.Cleanup(func() { SetEnabledForTest(prev) })
	ctx := ctxWith(t,
		[]string{"tenants/acme/*"},
		[]string{"tenants/acme/forbidden-*"},
		ClaimAllowedKeyPatterns, ClaimDenyKeyPatterns,
	)
	require.NoError(t, AuthorizeKey(ctx, "tenants/acme/ok-1"))
	err := AuthorizeKey(ctx, "tenants/acme/forbidden-1")
	require.Error(t, err)
	require.True(t, IsForbidden(err))
}

func TestAuthorizePolicy_UsesPolicyClaims(t *testing.T) {
	prev := SetEnabledForTest(true)
	t.Cleanup(func() { SetEnabledForTest(prev) })
	ctx := ctxWith(t, []string{"strict/*"}, nil, ClaimAllowedPolicyPatterns, ClaimDenyPolicyPatterns)
	require.NoError(t, AuthorizePolicy(ctx, "strict/aes"))
	require.Error(t, AuthorizePolicy(ctx, "loose/aes"))
}

func TestAuthorize_NoClaimsButEnabled_Denies(t *testing.T) {
	prev := SetEnabledForTest(true)
	t.Cleanup(func() { SetEnabledForTest(prev) })
	err := AuthorizeKey(context.Background(), "any")
	require.Error(t, err)
	require.True(t, IsForbidden(err))
}
