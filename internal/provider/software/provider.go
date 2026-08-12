// Package software implements a provider.Backend backed by Go's standard crypto library
// plus the circl library for post-quantum algorithms (ML-DSA).
package software

import (
	"context"
	"fmt"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider"
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
	return []string{"ecdsa-p256-sha256-der", "ml-dsa-65"}
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
		pubDER   []byte
		privDER  []byte
		encoding string
		err      error
	)

	// Dispatch on the typed AlgorithmDetails oneof.
	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		if alg.Ecdsa.GetCurve() != types.EllipticCurve_ELLIPTIC_CURVE_P256 {
			return nil, errors.New(ctx, op, errors.CodeNotImplemented,
				"only P-256 curve supported")
		}
		pubDER, privDER, err = generateECDSAP256Key(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		encoding = "sec1" // ECDSA: x509.MarshalECPrivateKey (SEC1, RFC 5915)
	case *types.AlgorithmDetails_MlDsa:
		if alg.MlDsa.GetParameterSet() != types.MlDsaParameterSet_ML_DSA_65 {
			return nil, errors.New(ctx, op, errors.CodeNotImplemented,
				"only ML-DSA-65 parameter set supported")
		}
		pubDER, privDER, err = generateMLDSA65Key(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		encoding = "raw" // ML-DSA: circl native PrivateKey.Bytes(), not yet PKCS#8
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm type: %T", req.GetAlgorithm().GetAlgorithm()))
	}

	// Return key material to caller — provider is stateless, orchestrator stores the bytes.
	return &providerpb.GenerateKeyResponse{
		PublicKeyBytes: pubDER,
		KeyMaterial:    privDER,
		Output:         provider.NoOutput(encoding),
	}, nil
}

// Sign dispatches to the algorithm-specific sign implementation.
func (p *Provider) Sign(ctx context.Context, req *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	const op errors.Op = "software.(Provider).Sign"

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		if alg.Ecdsa.GetCurve() != types.EllipticCurve_ELLIPTIC_CURVE_P256 {
			return nil, errors.New(ctx, op, errors.CodeNotImplemented,
				"only P-256 curve supported for sign")
		}
		sig, err := signECDSAP256(ctx, req.GetKeyMaterial(), req.GetInput())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput("der")}, nil
	case *types.AlgorithmDetails_MlDsa:
		if alg.MlDsa.GetParameterSet() != types.MlDsaParameterSet_ML_DSA_65 {
			return nil, errors.New(ctx, op, errors.CodeNotImplemented,
				"only ML-DSA-65 parameter set supported for sign")
		}
		sig, err := signMLDSA65(ctx, req.GetKeyMaterial(), req.GetInput())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for sign: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// Verify dispatches to the algorithm-specific verify implementation.
func (p *Provider) Verify(ctx context.Context, req *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	const op errors.Op = "software.(Provider).Verify"

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		if alg.Ecdsa.GetCurve() != types.EllipticCurve_ELLIPTIC_CURVE_P256 {
			return nil, errors.New(ctx, op, errors.CodeNotImplemented,
				"only P-256 curve supported for verify")
		}
		valid, err := verifyECDSAP256(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_MlDsa:
		if alg.MlDsa.GetParameterSet() != types.MlDsaParameterSet_ML_DSA_65 {
			return nil, errors.New(ctx, op, errors.CodeNotImplemented,
				"only ML-DSA-65 parameter set supported for verify")
		}
		valid, err := verifyMLDSA65(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for verify: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// DigestSign signs a pre-computed digest — the provider does NOT hash.
// Dispatches on the typed AlgorithmDetails oneof, exactly like Sign; the
// digest and key material alone cannot select the signature scheme (a single
// RSA key is valid under both PSS and PKCS1v15), so hash_algorithm describes
// only the digest's origin, never the algorithm to dispatch on.
func (p *Provider) DigestSign(ctx context.Context, req *providerpb.DigestSignRequest) (*providerpb.DigestSignResponse, error) {
	const op errors.Op = "software.(Provider).DigestSign"

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		if alg.Ecdsa.GetCurve() != types.EllipticCurve_ELLIPTIC_CURVE_P256 {
			return nil, errors.New(ctx, op, errors.CodeNotImplemented,
				"only P-256 curve supported for digest sign")
		}
		sig, err := signECDSAP256Digest(ctx, req.GetKeyMaterial(), req.GetDigest())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.DigestSignResponse{Signature: sig, Output: provider.NoOutput("der")}, nil
	case *types.AlgorithmDetails_MlDsa:
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"DigestSign unsupported for ML-DSA: pure ML-DSA is not prehashable")
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for digest sign: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// DigestVerify verifies a signature over a pre-computed digest.
// Dispatches on the typed AlgorithmDetails oneof, exactly like Verify.
func (p *Provider) DigestVerify(ctx context.Context, req *providerpb.DigestVerifyRequest) (*providerpb.DigestVerifyResponse, error) {
	const op errors.Op = "software.(Provider).DigestVerify"

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		if alg.Ecdsa.GetCurve() != types.EllipticCurve_ELLIPTIC_CURVE_P256 {
			return nil, errors.New(ctx, op, errors.CodeNotImplemented,
				"only P-256 curve supported for digest verify")
		}
		valid, err := verifyECDSAP256Digest(ctx, req.GetKeyMaterial(), req.GetDigest(), req.GetSignature())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.DigestVerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_MlDsa:
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"DigestVerify unsupported for ML-DSA: pure ML-DSA is not prehashable")
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for digest verify: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// Compile-time assertion: Provider implements provider.Backend and the Signer
// capability. The software provider does not (yet) implement Cipher, Macer,
// Hasher, Randomizer, or KeyEstablisher.
var (
	_ provider.Backend = (*Provider)(nil)
	_ provider.Signer  = (*Provider)(nil)
)

// Compile-time assertion: Provider implements AlgorithmCapabilityProvider.
var _ provider.AlgorithmCapabilityProvider = (*Provider)(nil)
