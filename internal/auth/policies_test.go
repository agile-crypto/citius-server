package auth

import (
	"context"
	"regexp"
	"testing"

	zauth "github.com/agile-crypto/zitadel-grpc-auth"
	"github.com/stretchr/testify/require"
)

// claimsCtx wraps the upstream ContextWithClaims helper for tests.
func claimsCtx(t *testing.T, raw map[string]any) context.Context {
	t.Helper()
	return zauth.ContextWithClaims(context.Background(), zauth.NewClaims(raw))
}

func TestRequirePerm_Granted(t *testing.T) {
	ctx := claimsCtx(t, map[string]any{
		"sub":            "svc-tester",
		ClaimPermissions: []any{PermCryptoEncrypt},
	})
	c := zauth.ClaimsFromContext(ctx)
	require.NoError(t, requirePerm(PermCryptoEncrypt)(ctx, "/x/y", c))
}

func TestRequirePerm_Missing(t *testing.T) {
	ctx := claimsCtx(t, map[string]any{
		"sub":            "svc-tester",
		ClaimPermissions: []any{PermKeysRead},
	})
	c := zauth.ClaimsFromContext(ctx)
	err := requirePerm(PermCryptoEncrypt)(ctx, "/x/y", c)
	require.Error(t, err)
	require.True(t, IsForbidden(err), "expected forbidden, got %v", err)
}

func TestRequirePerm_NilClaims(t *testing.T) {
	err := requirePerm(PermCryptoEncrypt)(context.Background(), "/x/y", nil)
	require.Error(t, err)
	require.True(t, IsForbidden(err))
}

func TestPolicyRegistry_NoEmptySlices(t *testing.T) {
	for method, policies := range policyRegistry() {
		require.NotEmpty(t, policies, "method %s has no policies", method)
		for i, p := range policies {
			require.NotNil(t, p, "method %s has nil policy at index %d", method, i)
		}
	}
}

func TestPolicyRegistry_AllPermissionsAreKnown(t *testing.T) {
	known := map[string]struct{}{}
	for _, p := range AllPermissions() {
		known[p] = struct{}{}
	}
	// Every permission threaded through requirePerm is wrapped in a
	// closure, so we can't reflect the string directly. Instead we
	// invoke each policy with a stub claim set, parse the resulting
	// `missing permission "X"` error, and confirm X is a known key.
	stubCtx := claimsCtx(t, map[string]any{"sub": "svc-stub"}) // no perms
	stubClaims := zauth.ClaimsFromContext(stubCtx)
	re := regexp.MustCompile(`missing permission "([^"]+)"`)
	saw := 0
	for method, policies := range policyRegistry() {
		for _, p := range policies {
			err := p(stubCtx, method, stubClaims)
			require.Error(t, err, "method %s policy unexpectedly accepted no-perm caller", method)
			m := re.FindStringSubmatch(err.Error())
			if m == nil {
				// Non-permission policies (none today) would land here;
				// skip rather than misclassify.
				continue
			}
			saw++
			if _, ok := known[m[1]]; !ok {
				t.Errorf("method %s requires unknown permission %q", method, m[1])
			}
		}
	}
	require.Greater(t, saw, 0, "no permission policies seen — registry parsing stale?")
}
