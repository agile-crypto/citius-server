// Package providergrpc serves services.ProviderService.
//
// It reaches internal/provider only. The service has two halves with different
// needs — a read-only catalogue over the process-wide registry, and persisted
// CRUD over configured instances — which is why New takes two factories rather
// than one. A future read-only deployment can supply a stub instance manager
// without touching the handler.
package providergrpc

import (
	"context"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"

	"google.golang.org/grpc"
)

const newOp engerr.Op = "grpc/provider.New"

// New builds the handler from the provider catalogue factory and the
// per-request instance manager factory. Both must be non-nil.
//
// A nil argument returns CodeInvalidArgument.
func New(ctx context.Context, newCatalog provider.RegistryFactory, newInstances provider.InstanceManagerFactory) (*ProviderHandler, error) {
	switch {
	case newCatalog == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "provider registry factory is required")
	case newInstances == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "provider instance manager factory is required")
	}
	return &ProviderHandler{providers: newCatalog, instances: newInstances}, nil
}

// Register registers the service on reg.
func Register(reg grpc.ServiceRegistrar, h *ProviderHandler) {
	servicespb.RegisterProviderServiceServer(reg, h)
}
