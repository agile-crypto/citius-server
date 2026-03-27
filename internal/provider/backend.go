// Package provider defines the Backend interface — the Go-side contract
// that every crypto provider must implement.
//
// Request and response types are the proto-generated messages from
// gen/go/provider (proto/provider/*.proto).  This ensures 1:1 type identity
// with the gRPC wire format — no translation layer, no drift.
//
// Proto mapping:
//
//	Backend.GenerateKey     → KeyOrchestrationService.GenerateKey
//	Backend.DestroyKey      → KeyOrchestrationService.DestroyKey
//	Backend.ExportPublicKey → KeyOrchestrationService.ExportPublicKey
//	Backend.Sign            → CryptoService.Sign
//	Backend.Verify          → CryptoService.Verify
package provider

import (
	"context"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
)

// Backend is the Go interface that every crypto provider must implement.
//
// Method signatures use proto-generated request/response types from
// gen/go/provider, ensuring 1:1 correspondence with the gRPC service
// contracts (KeyOrchestrationService + CryptoService).
//
// For in-process Go providers (software, loopback): implement directly.
// For out-of-process gRPC providers: a thin adapter wraps the gRPC client
// stubs into this interface (forwarding proto messages 1:1).
//
// Key material sovereignty: GenerateKeyResponse.key_material is opaque to
// the core.  The orchestrator stores it as-is and passes it back in
// SignRequest.key_material / VerifyRequest.key_material.  Only the provider
// that generated the material knows how to interpret it.
//
// Name() and Type() are Go-level identity methods that correspond to
// ProviderIdentityService.GetInfo() in the full gRPC flow.  They exist
// as convenience methods for the in-process registry.
type Backend interface {
	Name() string
	Type() string
	GenerateKey(ctx context.Context, req *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error)
	DestroyKey(ctx context.Context, req *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error)
	ExportPublicKey(ctx context.Context, req *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error)
	Sign(ctx context.Context, req *providerpb.SignRequest) (*providerpb.SignResponse, error)
	Verify(ctx context.Context, req *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error)
}

// AlgorithmCapabilityProvider is an optional interface that provider
// implementations can implement to expose their supported algorithm IDs.
//
// This is currently a simplification of ProviderIdentityService.GetCapabilities().
// TODO: this will be replaced by the full GetCapabilities RPC.
//
// Providers that do NOT implement AlgorithmCapabilityProvider are gracefully
// skipped during template-based matching.
type AlgorithmCapabilityProvider interface {
	SupportedAlgorithms() []string
}
