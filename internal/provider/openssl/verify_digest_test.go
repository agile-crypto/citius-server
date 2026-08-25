package openssl_test

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

// TestVerifyDigest_notImplemented probes VerifyDigest's dispatch default
// case, mirroring TestSignDigest_notImplemented.
func TestVerifyDigest_notImplemented(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	digest := sha256.Sum256([]byte("message"))
	_, err = p.VerifyDigest(context.Background(), &providerpb.VerifyDigestRequest{
		Algorithm:     &types.AlgorithmDetails{},
		KeyMaterial:   []byte("placeholder"),
		Digest:        digest[:],
		Signature:     []byte("sig"),
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// TestVerifyDigest_validatesBeforeStub is the negative control for the
// validate-then-dispatch shape.
func TestVerifyDigest_validatesBeforeStub(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	_, err = p.VerifyDigest(context.Background(), &providerpb.VerifyDigestRequest{})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for missing algorithm, got: %v", err)
	}
}

// TestVerifyDigest_digestLengthMismatch is the negative control for
// validateDigestLength on the verify side.
func TestVerifyDigest_digestLengthMismatch(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	_, err = p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		Algorithm:           ecdsaP256Details(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Digest:              make([]byte, 20), // SHA-1-shaped, declared SHA-256
		Signature:           []byte("irrelevant"),
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a 20-byte digest declared SHA-256, got: %v", err)
	}
}

// TestVerifyDigest_ECDSA_verifiesSoftwareSignature completes the ECDSA
// digest-path bidirectional interop check: C10 proved openssl-signed
// digests verify with software; this proves the reverse.
func TestVerifyDigest_ECDSA_verifiesSoftwareSignature(t *testing.T) {
	tests := []struct {
		name   string
		alg    *types.AlgorithmDetails
		digest [32]byte
	}{
		{"p256-der", ecdsaP256Details(), sha256.Sum256([]byte("sign with software, verify with openssl"))},
		{"p256-p1363", ecdsaP256P1363Details(), sha256.Sum256([]byte("sign with software, verify with openssl (p1363)"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			sw := software.New()

			keyResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("software GenerateKey: %v", err)
			}

			signResp, err := sw.SignDigest(ctx, &providerpb.SignDigestRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetKeyMaterial(),
				KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
				Digest:              tt.digest[:],
				HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			})
			if err != nil {
				t.Fatalf("software SignDigest: %v", err)
			}

			p, err := openssl.New(ctx)
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetPublicKeyBytes(),
				KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
				Digest:              tt.digest[:],
				Signature:           signResp.GetSignature(),
				HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			})
			if err != nil {
				t.Fatalf("openssl VerifyDigest: %v", err)
			}
			if !verifyResp.GetValid() {
				t.Error("openssl rejected a digest signature software produced")
			}
		})
	}
}

// TestVerifyDigest_ECDSA_rejectsTamperedSignature is the negative control:
// a well-formed but wrong signature must come back valid=false, no error.
func TestVerifyDigest_ECDSA_rejectsTamperedSignature(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digestA := sha256.Sum256([]byte("the original message"))
	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           ecdsaP256Details(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              digestA[:],
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	digestB := sha256.Sum256([]byte("a different message"))
	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		Algorithm:           ecdsaP256Details(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Digest:              digestB[:],
		Signature:           signResp.GetSignature(),
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if err != nil {
		t.Fatalf("VerifyDigest returned an error for a wrong signature, want valid=false: %v", err)
	}
	if verifyResp.GetValid() {
		t.Error("openssl accepted a signature over a digest it was never computed for")
	}
}

// TestVerifyDigest_ECDSA_curveMismatch is the negative control for
// checkCurveMatches on the verify-digest path.
func TestVerifyDigest_ECDSA_curveMismatch(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256([]byte("message"))
	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           ecdsaP256Details(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              digest[:],
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	_, err = p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		Algorithm:           ecdsaP384Details(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Digest:              digest[:],
		Signature:           signResp.GetSignature(),
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a P-256 key declared as P-384, got: %v", err)
	}
}

// TestVerifyDigest_RSA_verifiesSoftwareSignature completes the RSA
// digest-path bidirectional interop check.
func TestVerifyDigest_RSA_verifiesSoftwareSignature(t *testing.T) {
	tests := []struct {
		name string
		alg  *types.AlgorithmDetails
	}{
		{"pss-2048", rsaPssDetails(2048)},
		{"pkcs1v15-2048", rsaPkcs1v15Details(2048)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			sw := software.New()

			keyResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("software GenerateKey: %v", err)
			}

			digest := sha256.Sum256([]byte("sign with software, verify with openssl"))
			signResp, err := sw.SignDigest(ctx, &providerpb.SignDigestRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetKeyMaterial(),
				KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
				Digest:              digest[:],
				HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			})
			if err != nil {
				t.Fatalf("software SignDigest: %v", err)
			}

			p, err := openssl.New(ctx)
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetPublicKeyBytes(),
				KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
				Digest:              digest[:],
				Signature:           signResp.GetSignature(),
				HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			})
			if err != nil {
				t.Fatalf("openssl VerifyDigest: %v", err)
			}
			if !verifyResp.GetValid() {
				t.Error("openssl rejected a digest signature software produced")
			}
		})
	}
}

// TestVerifyDigest_RSA_keySizeMismatch is the negative control for
// checkRSAKeySize on the verify-digest path.
func TestVerifyDigest_RSA_keySizeMismatch(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: rsaPssDetails(2048)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256([]byte("message"))
	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           rsaPssDetails(2048),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              digest[:],
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	_, err = p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		Algorithm:           rsaPssDetails(3072),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Digest:              digest[:],
		Signature:           signResp.GetSignature(),
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a 2048-bit key declared as 3072-bit, got: %v", err)
	}
}

// TestVerifyDigest_Ed25519PH_verifiesSoftwareSignature completes the
// Ed25519ph digest-path bidirectional interop check.
func TestVerifyDigest_Ed25519PH_verifiesSoftwareSignature(t *testing.T) {
	ctx := context.Background()
	sw := software.New()

	keyResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ed25519phDetails()})
	if err != nil {
		t.Fatalf("software GenerateKey: %v", err)
	}

	digest := sha512.Sum512([]byte("sign with software (ph), verify with openssl"))
	signResp, err := sw.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           ed25519phDetails(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              digest[:],
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA512,
	})
	if err != nil {
		t.Fatalf("software SignDigest: %v", err)
	}

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	verifyResp, err := p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		Algorithm:           ed25519phDetails(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Digest:              digest[:],
		Signature:           signResp.GetSignature(),
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA512,
	})
	if err != nil {
		t.Fatalf("openssl VerifyDigest: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("openssl rejected a digest signature software produced")
	}
}

// TestVerifyDigest_Ed25519_pureVariantRejected is the negative control for
// the Ed25519 prehashable-variant gate on the verify-digest path. See
// ed25519PureExplicitDetails' doc comment (sign_digest_test.go) for why
// PURE must be explicit rather than relying on the zero value.
func TestVerifyDigest_Ed25519_pureVariantRejected(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ed25519Details()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	digest := sha512.Sum512([]byte("message"))
	_, err = p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		Algorithm:           ed25519PureExplicitDetails(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Digest:              digest[:],
		Signature:           []byte("irrelevant"),
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA512,
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for pure Ed25519 (not prehashable), got: %v", err)
	}
}

// TestVerifyDigest_Ed25519PH_wrongHashRejected is the negative control for
// checkEd25519PHHash on the verify-digest path.
func TestVerifyDigest_Ed25519PH_wrongHashRejected(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ed25519phDetails()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	digest := sha512.Sum512([]byte("message"))
	_, err = p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		Algorithm:           ed25519phDetails(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Digest:              digest[:],
		Signature:           []byte("irrelevant"),
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA3_512,
	})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for a non-SHA-512 declared hash, got: %v", err)
	}
}

// TestVerifyDigest_MLDSA_rejected proves ML-DSA is rejected outright on the
// verify-digest path too, matching software's identical rejection.
func TestVerifyDigest_MLDSA_rejected(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: mlDSADetails(types.MlDsaParameterSet_ML_DSA_65)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	digest := sha256.Sum256([]byte("message"))
	_, err = p.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		Algorithm:           mlDSADetails(types.MlDsaParameterSet_ML_DSA_65),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Digest:              digest[:],
		Signature:           []byte("irrelevant"),
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for ML-DSA (not prehashable), got: %v", err)
	}
}
