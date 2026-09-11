package authz

import (
	"context"
	"errors"
	"testing"

	engerr "github.com/agile-crypto/citius-core/errors"
	citiusauth "github.com/agile-crypto/citius-server/internal/auth"
	zauth "github.com/agile-crypto/zitadel-grpc-auth"
	"github.com/stretchr/testify/require"
)

const testOp engerr.Op = "grpc.authz.test"

func authorizeKeyName(ctx context.Context, op engerr.Op, name string) error {
	fn := AuthorizeKeyName()
	return fn(ctx, op, name)
}

func authorizePolicyName(ctx context.Context, op engerr.Op, name string) error {
	fn := AuthorizePolicyName()
	return fn(ctx, op, name)
}

func ctxWithClaims(allow []string) context.Context {
	raw := map[string]any{"sub": "svc-tester"}
	if allow != nil {
		anyAllow := make([]any, len(allow))
		for i, v := range allow {
			anyAllow[i] = v
		}
		raw[citiusauth.ClaimAllowedKeyPatterns] = anyAllow
	}
	return zauth.ContextWithClaims(context.Background(), zauth.NewClaims(raw))
}

func TestAuthorizeKeyName_NoClaims_AllowsAll(t *testing.T) {
	prev := citiusauth.SetEnabledForTest(false)
	t.Cleanup(func() { citiusauth.SetEnabledForTest(prev) })
	require.NoError(t, authorizeKeyName(context.Background(), testOp, "any/key"))
}

func TestAuthorizeKeyName_ForbiddenMapsToPolicyViolation(t *testing.T) {
	prev := citiusauth.SetEnabledForTest(true)
	t.Cleanup(func() { citiusauth.SetEnabledForTest(prev) })
	ctx := ctxWithClaims(nil) // claims present, allow list empty -> deny
	err := authorizeKeyName(ctx, testOp, "tenants/acme/k1")
	require.Error(t, err)

	var e *engerr.Error
	require.True(t, errors.As(err, &e), "expected *engerr.Error, got %T", err)
	require.Equal(t, engerr.CodePolicyViolation, e.Code)
}

func TestAuthorizeKeyName_GrantedAllowGlob(t *testing.T) {
	prev := citiusauth.SetEnabledForTest(true)
	t.Cleanup(func() { citiusauth.SetEnabledForTest(prev) })
	ctx := ctxWithClaims([]string{"tenants/acme/*"})
	require.NoError(t, authorizeKeyName(ctx, testOp, "tenants/acme/k1"))
}

func TestAuthorizePolicyName_DelegatesToPolicyClaims(t *testing.T) {
	prev := citiusauth.SetEnabledForTest(true)
	t.Cleanup(func() { citiusauth.SetEnabledForTest(prev) })
	raw := map[string]any{
		"sub":                                 "svc-tester",
		citiusauth.ClaimAllowedPolicyPatterns: []any{"strict/*"},
	}
	ctx := zauth.ContextWithClaims(context.Background(), zauth.NewClaims(raw))
	require.NoError(t, authorizePolicyName(ctx, testOp, "strict/aes"))
	err := authorizePolicyName(ctx, testOp, "loose/aes")
	require.Error(t, err)
	var e *engerr.Error
	require.True(t, errors.As(err, &e))
	require.Equal(t, engerr.CodePolicyViolation, e.Code)
}
