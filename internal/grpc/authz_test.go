package grpc

import (
	"context"
	"errors"
	"testing"

	zauth "github.ibm.com/citius/zitadel-grpc-auth"
	citiusauth "github.ibm.com/citius/citius-server/internal/auth"
	engerr "github.ibm.com/citius/citius-server/internal/errors"
	"github.com/stretchr/testify/require"
)

const testOp engerr.Op = "grpc.authz.test"

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
	require.NoError(t, authorizeKeyName(context.Background(), testOp, "any/key"))
}

func TestAuthorizeKeyName_ForbiddenMapsToPolicyViolation(t *testing.T) {
	ctx := ctxWithClaims(nil) // claims present, allow list empty -> deny
	err := authorizeKeyName(ctx, testOp, "tenants/acme/k1")
	require.Error(t, err)

	var e *engerr.Error
	require.True(t, errors.As(err, &e), "expected *engerr.Error, got %T", err)
	require.Equal(t, engerr.CodePolicyViolation, e.Code)
}

func TestAuthorizeKeyName_GrantedAllowGlob(t *testing.T) {
	ctx := ctxWithClaims([]string{"tenants/acme/*"})
	require.NoError(t, authorizeKeyName(ctx, testOp, "tenants/acme/k1"))
}

func TestAuthorizePolicyName_DelegatesToPolicyClaims(t *testing.T) {
	raw := map[string]any{
		"sub": "svc-tester",
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
