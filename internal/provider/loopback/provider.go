// Package loopback provides a deterministic provider.Backend implementation for testing.
// It does not perform real cryptography. Never use in production.
//
// The loopback provider is designed to make integration tests hermetic and deterministic:
//   - GenerateKey returns synthetic fixed bytes ("LOOPBACK_PUB", "LOOPBACK_PRIV")
//   - Sign echoes the input bytes as the signature
//   - Verify returns true iff signature == input (the loopback invariant)
//
// This allows verifying the full CreateKey=>Sign=>Verify flow without any real crypto.
package loopback

import (
	"bytes"
	"context"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
	"github.ibm.com/citius/citius-server/internal/provider"
)

// Provider is a loopback provider.Backend implementation.
// Sign echoes the input as the signature; Verify checks input == signature.
type Provider struct{}

// New returns a new loopback Provider.
func New() *Provider { return &Provider{} }

// Name returns the provider's unique name.
func (p *Provider) Name() string { return "loopback" }

// Type returns the provider type identifier.
func (p *Provider) Type() string { return "loopback" }

// SupportedAlgorithms returns the algorithm IDs this provider handles.
// IDs must exactly match TemplateID values in the standard algorithm catalog JSON.
func (p *Provider) SupportedAlgorithms() []string {
	return []string{"ecdsa-p256-sha256-der", "ml-dsa-65"}
}

// GenerateKey returns synthetic deterministic bytes — no real key material.
func (p *Provider) GenerateKey(_ context.Context, _ *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return &providerpb.GenerateKeyResponse{
		PublicKeyBytes: []byte("LOOPBACK_PUB"),
		KeyMaterial:    []byte("LOOPBACK_PRIV"),
	}, nil
}

// DestroyKey is a no-op for the loopback provider.
func (p *Provider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}

// ExportPublicKey returns deterministic public key bytes.
func (p *Provider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return &providerpb.ExportPublicKeyResponse{
		PublicKeyBytes: []byte("LOOPBACK_PUB"),
	}, nil
}

// Sign echoes the input as the "signature".
// This makes round-trip testing trivial: Verify succeeds when signature == input.
func (p *Provider) Sign(_ context.Context, req *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return &providerpb.SignResponse{Signature: req.GetInput()}, nil
}

// Verify returns valid=true when signature == input (the loopback invariant from Sign).
func (p *Provider) Verify(_ context.Context, req *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return &providerpb.VerifyResponse{
		Valid: bytes.Equal(req.GetSignature(), req.GetInput()),
	}, nil
}

// Compile-time assertions.
var (
	_ provider.Backend                     = (*Provider)(nil)
	_ provider.AlgorithmCapabilityProvider = (*Provider)(nil)
)
