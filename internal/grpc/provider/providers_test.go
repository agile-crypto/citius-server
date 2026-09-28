package providergrpc_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func providerIDs(resp *servicespb.ListProvidersResponse) []string {
	ids := make([]string, 0, len(resp.GetProviders()))
	for _, p := range resp.GetProviders() {
		ids = append(ids, p.GetProviderId())
	}
	return ids
}

func TestListProviders(t *testing.T) {
	h, _ := newProviders(t)
	ctx := context.Background()

	for name, tc := range map[string]struct {
		req  *servicespb.ListProvidersRequest
		want []string
	}{
		"all":         {req: &servicespb.ListProvidersRequest{}, want: []string{"openssl", "software"}},
		"by template": {req: &servicespb.ListProvidersRequest{TemplateId: "ml-dsa-65"}, want: []string{"openssl", "software"}},
		"by FIPS 140": {req: &servicespb.ListProvidersRequest{Requirements: &typespb.ProviderRequirements{
			Fips_140Certified: proto.Bool(true),
		}}, want: []string{"openssl"}},
		// openssl-fips is FIPS but does not advertise ml-dsa-65; openssl
		// advertises it but is not FIPS. No one instance has both.
		"both on one instance": {req: &servicespb.ListProvidersRequest{TemplateId: "ml-dsa-65", Requirements: &typespb.ProviderRequirements{
			Fips_140Certified: proto.Bool(true),
		}}, want: []string{}},
		"paged": {req: &servicespb.ListProvidersRequest{PageSize: 1, PageToken: "1"}, want: []string{"software"}},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := h.ListProviders(ctx, tc.req)
			require.NoError(t, err)
			require.Equal(t, tc.want, providerIDs(resp))
		})
	}
}

func TestGetProvider(t *testing.T) {
	h, _ := newProviders(t)
	ctx := context.Background()

	resp, err := h.GetProvider(ctx, &servicespb.GetProviderRequest{ProviderId: "openssl"})
	require.NoError(t, err)
	support := map[string]string{}
	for _, s := range resp.GetProvider().GetTemplateSupport() {
		support[s.GetTemplateId()] = s.GetNotes()
	}
	require.Equal(t, map[string]string{
		"aes-256-gcm": "instances: openssl, openssl-fips",
		"ml-dsa-65":   "instances: openssl",
	}, support)

	_, err = h.GetProvider(ctx, &servicespb.GetProviderRequest{ProviderId: "openssl-fips"})
	require.Equal(t, codes.NotFound, status.Code(err), "an instance is not a provider")
	_, err = h.GetProvider(ctx, &servicespb.GetProviderRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
