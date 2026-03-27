// Package software implements a provider.Backend backed by Go's standard crypto library
// plus the circl library for post-quantum algorithms (ML-DSA).
package software

import (
	"context"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/provider"
)

// Provider is a stateless software-backed provider.Backend implementation.
// Key material is NOT stored internally — the orchestrator manages persistence.
type Provider struct{}

// New creates a new software Provider.
func New() *Provider {
	return &Provider{}
}

func (p *Provider) Name() string { return "software" }
func (p *Provider) Type() string { return "software" }

// SupportedAlgorithms returns the algorithm IDs this provider handles.
// These IDs must exactly match the TemplateID values in the template catalog JSON.
func (p *Provider) SupportedAlgorithms() []string {
	return []string{"ecdsa-p256-sha256", "ml-dsa-65"}
}

// DestroyKey is a no-op for the stateless software provider.
// The orchestrator manages key lifecycle; the provider has no internal state.
func (p *Provider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}

// ExportPublicKey may/may-not supported by the stateless software provider.
// The orchestrator already has the public key bytes from GenerateKey.
func (p *Provider) ExportPublicKey(ctx context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	const op errors.Op = "software.Provider.ExportPublicKey"
	return nil, errors.New(ctx, op, errors.CodeNotImplemented,
		"ExportPublicKey not supported: provider is stateless, orchestrator has the key bytes")
}

// GenerateKey stub - TODO: Implement
func (p *Provider) GenerateKey(ctx context.Context, _ *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	const op errors.Op = "software.Provider.GenerateKey"
	return nil, errors.New(ctx, op, errors.CodeNotImplemented,
		"GenerateKey not yet implemented")
}

// Sign stub - TODO: Implement
func (p *Provider) Sign(ctx context.Context, _ *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	const op errors.Op = "software.Provider.Sign"
	return nil, errors.New(ctx, op, errors.CodeNotImplemented,
		"Sign not yet implemented")
}

// Verify stub - TODO: Implement
func (p *Provider) Verify(ctx context.Context, _ *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	const op errors.Op = "software.Provider.Verify"
	return nil, errors.New(ctx, op, errors.CodeNotImplemented,
		"Verify not yet implemented")
}

// Compile-time assertion: Provider implements provider.Backend.
var _ provider.Backend = (*Provider)(nil)

// Compile-time assertion: Provider implements AlgorithmCapabilityProvider.
var _ provider.AlgorithmCapabilityProvider = (*Provider)(nil)
