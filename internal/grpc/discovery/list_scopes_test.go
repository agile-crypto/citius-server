package discogrpc_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/template"
)

func TestListScopes_OnlyOfferedScopesWithTheirOperations(t *testing.T) {
	h, reg := newDiscovery(t)
	// A template without a scope contributes nothing, and does not fail the call.
	reg.list = append(reg.list, template.NewTemplate(&typespb.TemplateInfo{
		TemplateId:         "broken",
		ScopedCapabilities: []*typespb.ScopedCapabilities{{}},
	}))

	resp, err := h.ListScopes(context.Background(), &servicespb.ListScopesRequest{})
	require.NoError(t, err)

	got := map[string][]typespb.CryptoOperation{}
	names := []string{}
	for _, s := range resp.GetScopes() {
		names = append(names, s.GetName())
		got[s.GetName()] = s.GetSupportedOperations()
		require.NotNil(t, s.GetSpecification(), s.GetName())
	}
	require.Equal(t, []string{"signature_standard", "aead_standard"}, names, "enum order, offered scopes only")
	require.Equal(t, []typespb.CryptoOperation{
		typespb.CryptoOperation_CRYPTO_OPERATION_ENCRYPT, typespb.CryptoOperation_CRYPTO_OPERATION_DECRYPT,
	}, got["aead_standard"], "operations are merged across templates, once each")
}
