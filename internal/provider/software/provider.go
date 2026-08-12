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
		pubDER  []byte
		privDER []byte
		privEnc providerpb.PrivateKeyEncoding
		pubEnc  providerpb.PublicKeyEncoding
		err     error
	)

	// Dispatch on the typed AlgorithmDetails oneof.
	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		pubDER, privDER, err = generateECDSAKey(ctx, alg.Ecdsa.GetCurve())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		// The two halves differ: x509.MarshalECPrivateKey writes SEC1
		// (RFC 5915) while x509.MarshalPKIXPublicKey writes SPKI (RFC 5280).
		privEnc = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI
	case *types.AlgorithmDetails_MlDsa:
		if alg.MlDsa.GetParameterSet() != types.MlDsaParameterSet_ML_DSA_65 {
			return nil, errors.New(ctx, op, errors.CodeNotImplemented,
				"only ML-DSA-65 parameter set supported")
		}
		pubDER, privDER, err = generateMLDSA65Key(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		// ML-DSA: circl native Bytes() for both halves, not yet PKCS#8/SPKI.
		privEnc = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_RAW
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm type: %T", req.GetAlgorithm().GetAlgorithm()))
	}

	// Return key material to caller — provider is stateless, orchestrator stores the bytes.
	// Output carries no encoding: key generation produces no operation artifact,
	// and the key encodings are declared by the typed fields below.
	return &providerpb.GenerateKeyResponse{
		PublicKeyBytes:      pubDER,
		KeyMaterial:         privDER,
		Output:              provider.NoOutputUnencoded(),
		KeyMaterialEncoding: privEnc,
		PublicKeyEncoding:   pubEnc,
	}, nil
}

// Sign dispatches to the algorithm-specific sign implementation.
func (p *Provider) Sign(ctx context.Context, req *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	const op errors.Op = "software.(Provider).Sign"

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		sig, err := signECDSA(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetKeyMaterialEncoding(),
			alg.Ecdsa.GetCurve(), alg.Ecdsa.GetHash())
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
		valid, err := verifyECDSA(ctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), alg.Ecdsa.GetCurve(), alg.Ecdsa.GetHash())
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

// validateDigestLength rejects a digest whose length contradicts the
// declared hash algorithm (e.g. a 20-byte digest claiming to be SHA-256,
// which must be 32 bytes).  Hash algorithms with no fixed length
// (UNSPECIFIED, OTHER, the SHAKE XOFs) are not checked — the caller declared
// no fixed-length hash, so there is nothing to validate the digest against.
func validateDigestLength(ctx context.Context, op errors.Op, hashAlg types.HashAlgorithm, digestLen int) error {
	wantLen, ok := provider.DigestLengthForHash(hashAlg)
	if !ok {
		return nil
	}
	if digestLen != wantLen {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("digest length %d bytes does not match expected length %d bytes for %s",
				digestLen, wantLen, hashAlg))
	}
	return nil
}

// DigestSign signs a pre-computed digest — the provider does NOT hash.
// Dispatches on the typed AlgorithmDetails oneof, exactly like Sign; the
// digest and key material alone cannot select the signature scheme (a single
// RSA key is valid under both PSS and PKCS1v15), so hash_algorithm describes
// only the digest's origin, never the algorithm to dispatch on.
func (p *Provider) DigestSign(ctx context.Context, req *providerpb.DigestSignRequest) (*providerpb.DigestSignResponse, error) {
	const op errors.Op = "software.(Provider).DigestSign"

	if err := validateDigestLength(ctx, op, req.GetHashAlgorithm(), len(req.GetDigest())); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		sig, err := signECDSADigest(ctx, req.GetKeyMaterial(), req.GetDigest(), req.GetKeyMaterialEncoding(),
			alg.Ecdsa.GetCurve())
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

	if err := validateDigestLength(ctx, op, req.GetHashAlgorithm(), len(req.GetDigest())); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		valid, err := verifyECDSADigest(ctx, req.GetKeyMaterial(), req.GetDigest(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), alg.Ecdsa.GetCurve())
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
