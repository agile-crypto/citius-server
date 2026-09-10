package keyestgrpc

import (
	"context"

	messagespb "github.com/agile-crypto/citius-server/gen/go/api/messages"
	servicespb "github.com/agile-crypto/citius-server/gen/go/api/services"
	"github.com/agile-crypto/citius-server/internal/service"
)

// KeyEstablishmentHandler serves services.KeyEstablishmentService — wrapping,
// unwrapping, derivation, agreement and KEM encapsulation.
//
// This service straddles two capabilities, which is why it is its own handler:
// the operations themselves are cryptographic (service.CryptoOrchestratorFactory), but every one of
// them either consumes or produces a managed key, so the resulting key material
// must be registered through the key orchestrator (service.KeyOrchestratorFactory).
//
// Immutable after construction, safe for concurrent use.
type KeyEstablishmentHandler struct {
	crypto service.CryptoOrchestratorFactory
	keys   service.KeyOrchestratorFactory
	servicespb.UnimplementedKeyEstablishmentServiceServer
}

var _ servicespb.KeyEstablishmentServiceServer = (*KeyEstablishmentHandler)(nil)

// const keyEstablishmentHandlerOp = engerr.Op("grpc.(KeyEstablishmentHandler)")

// WrapKey handles the WrapKey RPC.
func (h *KeyEstablishmentHandler) WrapKey(ctx context.Context, req *messagespb.WrapKeyRequest) (*messagespb.WrapKeyResponse, error) {
	return h.UnimplementedKeyEstablishmentServiceServer.WrapKey(ctx, req)
}

// UnwrapKey handles the UnwrapKey RPC.
func (h *KeyEstablishmentHandler) UnwrapKey(ctx context.Context, req *messagespb.UnwrapKeyRequest) (*messagespb.UnwrapKeyResponse, error) {
	return h.UnimplementedKeyEstablishmentServiceServer.UnwrapKey(ctx, req)
}

// DeriveKey handles the DeriveKey RPC.
func (h *KeyEstablishmentHandler) DeriveKey(ctx context.Context, req *messagespb.DeriveKeyRequest) (*messagespb.DeriveKeyResponse, error) {
	return h.UnimplementedKeyEstablishmentServiceServer.DeriveKey(ctx, req)
}

// KeyAgreement handles the KeyAgreement RPC.
func (h *KeyEstablishmentHandler) KeyAgreement(ctx context.Context, req *messagespb.KeyAgreementRequest) (*messagespb.KeyAgreementResponse, error) {
	return h.UnimplementedKeyEstablishmentServiceServer.KeyAgreement(ctx, req)
}

// EncapsulateKey handles the EncapsulateKey RPC.
func (h *KeyEstablishmentHandler) EncapsulateKey(ctx context.Context, req *messagespb.EncapsulateKeyRequest) (*messagespb.EncapsulateKeyResponse, error) {
	return h.UnimplementedKeyEstablishmentServiceServer.EncapsulateKey(ctx, req)
}

// DecapsulateKey handles the DecapsulateKey RPC.
func (h *KeyEstablishmentHandler) DecapsulateKey(ctx context.Context, req *messagespb.DecapsulateKeyRequest) (*messagespb.DecapsulateKeyResponse, error) {
	return h.UnimplementedKeyEstablishmentServiceServer.DecapsulateKey(ctx, req)
}
