package providergrpc_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	providergrpc "github.com/agile-crypto/citius-server/internal/grpc/provider"
)

// fakeBackend is a registrable Backend that advertises templates and
// implementation properties; its key operations are never called.
type fakeBackend struct {
	name, typ string
	templates []string
	impl      *typespb.ImplementationProperties
}

func (b *fakeBackend) Name() string { return b.name }
func (b *fakeBackend) Type() string { return b.typ }
func (b *fakeBackend) GenerateKey(context.Context, *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	panic("not used")
}
func (b *fakeBackend) DestroyKey(context.Context, *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	panic("not used")
}
func (b *fakeBackend) ExportPublicKey(context.Context, *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	panic("not used")
}
func (b *fakeBackend) SupportedAlgorithms() []string { return b.templates }
func (b *fakeBackend) ImplementationProperties() *typespb.ImplementationProperties {
	return b.impl
}

func fips(level typespb.Fips140Level) *typespb.ImplementationProperties {
	return &typespb.ImplementationProperties{Fips_140: &typespb.Fips140Certification{Certified: true, Level: level}}
}

// newProviders registers, out of name order: software (no properties),
// openssl-fips (FIPS 140 level 1, hardware accelerated) and openssl.
func newProviders(t *testing.T) (*providergrpc.ProviderHandler, provider.Registry) {
	t.Helper()
	ctx := context.Background()
	reg := provider.NewRegistry()
	for _, b := range []*fakeBackend{
		{name: "software", typ: "software", templates: []string{"aes-256-gcm", "ml-dsa-65"}},
		{name: "openssl-fips", typ: "openssl", templates: []string{"aes-256-gcm"}, impl: func() *typespb.ImplementationProperties {
			p := fips(typespb.Fips140Level_FIPS_140_LEVEL_1)
			p.HardwareAccelerated = proto.Bool(true)
			return p
		}()},
		{name: "openssl", typ: "openssl", templates: []string{"aes-256-gcm", "ml-dsa-65"}, impl: &typespb.ImplementationProperties{HardwareAccelerated: proto.Bool(true)}},
	} {
		require.NoError(t, reg.Register(ctx, b))
	}
	h, err := providergrpc.New(ctx,
		func(context.Context) (provider.Registry, error) { return reg, nil },
		func(context.Context) (provider.InstanceManager, error) { return nil, nil })
	require.NoError(t, err)
	return h, reg
}

func instanceIDs(in []*typespb.ProviderInstance) []string {
	ids := make([]string, 0, len(in))
	for _, i := range in {
		ids = append(ids, i.GetInstanceId())
	}
	return ids
}

func TestListProviderInstances(t *testing.T) {
	h, _ := newProviders(t)
	ctx := context.Background()

	for name, tc := range map[string]struct {
		req  *servicespb.ListProviderInstancesRequest
		want []string
	}{
		"all, by ID":    {req: &servicespb.ListProviderInstancesRequest{}, want: []string{"openssl", "openssl-fips", "software"}},
		"by provider":   {req: &servicespb.ListProviderInstancesRequest{ProviderId: "openssl"}, want: []string{"openssl", "openssl-fips"}},
		"FIPS 140 only": {req: &servicespb.ListProviderInstancesRequest{Requirements: &typespb.ProviderRequirements{Fips_140Certified: proto.Bool(true)}}, want: []string{"openssl-fips"}},
		"one page":      {req: &servicespb.ListProviderInstancesRequest{PageSize: 1, PageToken: "1"}, want: []string{"openssl-fips"}},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := h.ListProviderInstances(ctx, tc.req)
			require.NoError(t, err)
			require.Equal(t, tc.want, instanceIDs(resp.GetInstances()))
		})
	}
}

func TestListProviderInstances_ReportsEachInstancesImplementation(t *testing.T) {
	h, _ := newProviders(t)
	resp, err := h.ListProviderInstances(context.Background(), &servicespb.ListProviderInstancesRequest{ProviderId: "openssl"})
	require.NoError(t, err)
	byID := map[string]*typespb.ProviderInstance{}
	for _, i := range resp.GetInstances() {
		byID[i.GetInstanceId()] = i
	}
	require.Equal(t, "openssl", byID["openssl-fips"].GetProviderId())
	require.True(t, byID["openssl-fips"].GetImplementationOverride().GetFips_140().GetCertified())
	require.False(t, byID["openssl"].GetImplementationOverride().GetFips_140().GetCertified())
}

func TestListProviderInstances_InvalidRequests(t *testing.T) {
	h, _ := newProviders(t)
	for name, req := range map[string]*servicespb.ListProviderInstancesRequest{
		"negative page_size":      {PageSize: -1},
		"bad page_token":          {PageToken: "z"},
		"additional requirements": {Requirements: &typespb.ProviderRequirements{Additional: map[string]string{"k": "v"}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.ListProviderInstances(context.Background(), req)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestGetProviderInstance(t *testing.T) {
	h, _ := newProviders(t)
	ctx := context.Background()

	resp, err := h.GetProviderInstance(ctx, &servicespb.GetProviderInstanceRequest{InstanceId: "openssl-fips"})
	require.NoError(t, err)
	require.Equal(t, "openssl", resp.GetInstance().GetProviderId())

	_, err = h.GetProviderInstance(ctx, &servicespb.GetProviderInstanceRequest{InstanceId: "hsm"})
	require.Equal(t, codes.NotFound, status.Code(err))
	_, err = h.GetProviderInstance(ctx, &servicespb.GetProviderInstanceRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// A response is a copy: editing it leaves the backend's properties alone.
func TestGetProviderInstance_ReturnsCopies(t *testing.T) {
	h, reg := newProviders(t)
	ctx := context.Background()
	resp, err := h.GetProviderInstance(ctx, &servicespb.GetProviderInstanceRequest{InstanceId: "openssl-fips"})
	require.NoError(t, err)
	resp.GetInstance().GetImplementationOverride().GetFips_140().Certified = false

	b, err := reg.Get(ctx, "openssl-fips")
	require.NoError(t, err)
	require.True(t, provider.ImplementationOf(b).GetFips_140().GetCertified())
}
