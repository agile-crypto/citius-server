// Package keyestgrpc serves services.KeyEstablishmentService — wrapping,
// unwrapping, derivation, agreement and KEM encapsulation.
//
// It is the one service needing two capabilities: the operations are
// cryptographic, but each consumes or produces managed key material, so the
// result must be registered through the key orchestrator. That two-factory
// constructor is the reason this is its own package rather than part of
// cryptogrpc — the dependency belongs to this service, not to sign/verify.
package keyestgrpc

import (
	"context"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/service"

	"google.golang.org/grpc"
)

const newOp engerr.Op = "grpc/keyestablishment.New"

// New builds the handler from the crypto orchestrator factory that performs the
// primitive operations and the key orchestrator factory that manages the key
// material they consume or produce. Both must be non-nil.
//
// A nil argument returns CodeInvalidArgument.
func New(ctx context.Context, newCrypto service.CryptoOrchestratorFactory, newKeys service.KeyOrchestratorFactory) (*KeyEstablishmentHandler, error) {
	switch {
	case newCrypto == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "crypto orchestrator factory is required")
	case newKeys == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "key orchestrator factory is required")
	}
	return &KeyEstablishmentHandler{crypto: newCrypto, keys: newKeys}, nil
}

// Register registers the service on reg.
func Register(reg grpc.ServiceRegistrar, h *KeyEstablishmentHandler) {
	servicespb.RegisterKeyEstablishmentServiceServer(reg, h)
}
