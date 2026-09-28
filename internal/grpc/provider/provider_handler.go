package providergrpc

import (
	"context"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"
)

// ProviderHandler serves services.ProviderService — both the read-only provider
// catalogue (ListProviders, GetProvider, MatchProviders) and the CRUD over
// configured provider instances.
//
// It needs two capabilities: the process-wide provider registry for the
// catalogue and matching RPCs, and a per-request provider.InstanceManager for
// the instance CRUD, which is persisted and therefore storage-backed.
//
// Immutable after construction, safe for concurrent use.
type ProviderHandler struct {
	providers provider.RegistryFactory
	instances provider.InstanceManagerFactory
	servicespb.UnimplementedProviderServiceServer
}

var _ servicespb.ProviderServiceServer = (*ProviderHandler)(nil)

const providerHandlerOp = engerr.Op("grpc.(ProviderHandler)")

// RegisterProviderInstance handles the RegisterProviderInstance RPC.
func (h *ProviderHandler) RegisterProviderInstance(ctx context.Context, req *servicespb.RegisterProviderInstanceRequest) (*servicespb.RegisterProviderInstanceResponse, error) {
	return h.UnimplementedProviderServiceServer.RegisterProviderInstance(ctx, req)
}

// UpdateProviderInstance handles the UpdateProviderInstance RPC.
func (h *ProviderHandler) UpdateProviderInstance(ctx context.Context, req *servicespb.UpdateProviderInstanceRequest) (*servicespb.UpdateProviderInstanceResponse, error) {
	return h.UnimplementedProviderServiceServer.UpdateProviderInstance(ctx, req)
}

// DeleteProviderInstance handles the DeleteProviderInstance RPC.
func (h *ProviderHandler) DeleteProviderInstance(ctx context.Context, req *servicespb.DeleteProviderInstanceRequest) (*servicespb.DeleteProviderInstanceResponse, error) {
	return h.UnimplementedProviderServiceServer.DeleteProviderInstance(ctx, req)
}
