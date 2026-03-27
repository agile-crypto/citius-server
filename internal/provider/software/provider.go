// Package software implements a provider.Backend backed by Go's standard crypto library
// plus the circl library for post-quantum algorithms (ML-DSA).
package software

import (
	"context"
	"fmt"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
	types "github.ibm.com/citius/citius-server/gen/go/types"
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

// GenerateKey generates a key pair for the given algorithm and returns the key material.
// The provider is stateless — key material is returned to the caller (orchestrator) for storage.
func (p *Provider) GenerateKey(ctx context.Context, req *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	const op errors.Op = "software.(Provider).GenerateKey"

	var (
		pubDER  []byte
		privDER []byte
		err     error
	)

	// Dispatch on the typed AlgorithmDetails oneof.
	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		if alg.Ecdsa.GetCurve() != types.EllipticCurve_ELLIPTIC_CURVE_P256 {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
				"only P-256 curve supported")
		}
		pubDER, privDER, err = generateECDSAP256Key(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
	case *types.AlgorithmDetails_MlDsa:
		_ = alg // TODO: Implement
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			"ml-dsa key generation not yet implemented")
	default:
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("unsupported algorithm type: %T", req.GetAlgorithm().GetAlgorithm()))
	}

	// Return key material to caller — provider is stateless, orchestrator stores the bytes.
	return &providerpb.GenerateKeyResponse{
		PublicKeyBytes: pubDER,
		KeyMaterial:    privDER,
	}, nil
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
