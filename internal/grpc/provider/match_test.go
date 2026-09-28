package providergrpc_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/provider"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func matchIDs(resp *servicespb.MatchProvidersResponse) []string {
	ids := make([]string, 0, len(resp.GetMatches()))
	for _, m := range resp.GetMatches() {
		ids = append(ids, m.GetInstance().GetInstanceId())
	}
	return ids
}

func TestMatchProviders(t *testing.T) {
	h, _ := newProviders(t)
	ctx := context.Background()

	for name, tc := range map[string]struct {
		req  *servicespb.MatchProvidersRequest
		want []string
	}{
		"template only, registration order": {
			req:  &servicespb.MatchProvidersRequest{TemplateId: "aes-256-gcm"},
			want: []string{"software", "openssl-fips", "openssl"},
		},
		"template not everywhere": {
			req:  &servicespb.MatchProvidersRequest{TemplateId: "ml-dsa-65"},
			want: []string{"software", "openssl"},
		},
		"hard requirement drops the rest": {
			req: &servicespb.MatchProvidersRequest{TemplateId: "aes-256-gcm", Requirements: &typespb.ProviderRequirements{
				Fips_140Certified: proto.Bool(true),
			}},
			want: []string{"openssl-fips"},
		},
		"preference moves accelerated instances first": {
			req: &servicespb.MatchProvidersRequest{TemplateId: "aes-256-gcm", Requirements: &typespb.ProviderRequirements{
				PreferHardwareAccelerated: proto.Bool(true),
			}},
			want: []string{"openssl-fips", "openssl", "software"},
		},
		"unknown template": {
			req:  &servicespb.MatchProvidersRequest{TemplateId: "rot13"},
			want: []string{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := h.MatchProviders(ctx, tc.req)
			require.NoError(t, err)
			require.Equal(t, tc.want, matchIDs(resp))
		})
	}
}

// The first match is the instance the registry's Match — what CreateKey
// uses — picks for the same template and requirements.
func TestMatchProviders_FirstIsWhatCreateKeyPicks(t *testing.T) {
	h, reg := newProviders(t)
	ctx := context.Background()

	for _, prefer := range []bool{false, true} {
		req := &typespb.ProviderRequirements{PreferHardwareAccelerated: proto.Bool(prefer)}
		resp, err := h.MatchProviders(ctx, &servicespb.MatchProvidersRequest{TemplateId: "aes-256-gcm", Requirements: req})
		require.NoError(t, err)

		impl, err := core.ProviderRequirementsFromProto(ctx, req)
		require.NoError(t, err)
		picked, err := reg.Match(ctx, provider.Requirements{TemplateID: "aes-256-gcm", Implementation: impl})
		require.NoError(t, err)
		require.Equal(t, picked.Name(), resp.GetMatches()[0].GetInstance().GetInstanceId(), "prefer=%v", prefer)
	}
}

func TestMatchProviders_ScoresAndImplementation(t *testing.T) {
	h, _ := newProviders(t)
	resp, err := h.MatchProviders(context.Background(), &servicespb.MatchProvidersRequest{
		TemplateId:   "aes-256-gcm",
		Requirements: &typespb.ProviderRequirements{PreferHardwareAccelerated: proto.Bool(true)},
	})
	require.NoError(t, err)
	m := resp.GetMatches()
	require.Greater(t, m[0].GetMatchScore(), m[2].GetMatchScore())
	require.True(t, m[0].GetResolvedImplementation().GetFips_140().GetCertified())
}

func TestMatchProviders_InvalidRequirements(t *testing.T) {
	h, _ := newProviders(t)
	_, err := h.MatchProviders(context.Background(), &servicespb.MatchProvidersRequest{
		Requirements: &typespb.ProviderRequirements{Additional: map[string]string{"k": "v"}},
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
