package openssl_test

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

// TestSignDigest_notImplemented probes SignDigest's dispatch default case:
// every real algorithm arm now has a case (ECDSA, RSA-PSS, RSA-PKCS1v15,
// Ed25519, ML-DSA), so an AlgorithmDetails whose oneof is present but empty
// is the only shape left that still reaches default.
func TestSignDigest_notImplemented(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	digest := sha256.Sum256([]byte("message"))
	_, err = p.SignDigest(context.Background(), &providerpb.SignDigestRequest{
		Algorithm:     &types.AlgorithmDetails{},
		KeyMaterial:   []byte("placeholder"),
		Digest:        digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// TestSignDigest_validatesBeforeStub is the negative control for the
// validate-then-dispatch shape: a request missing Algorithm entirely must
// fail with CodeInvalidArgument, not CodeNotImplemented — proving
// validateRequest genuinely runs first.
func TestSignDigest_validatesBeforeStub(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	_, err = p.SignDigest(context.Background(), &providerpb.SignDigestRequest{})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for missing algorithm, got: %v", err)
	}
}

// TestSignDigest_digestLengthMismatch is the negative control for
// validateDigestLength: a digest whose length contradicts its declared
// hash_algorithm must be rejected before it reaches any provider-specific
// signing code.
func TestSignDigest_digestLengthMismatch(t *testing.T) {
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

	_, err = p.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           ecdsaP256Details(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              make([]byte, 20), // SHA-1-shaped, declared SHA-256
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a 20-byte digest declared SHA-256, got: %v", err)
	}
}

// TestSignDigest_ECDSA_verifiesWithSoftware signs a digest the test computes
// itself (not via openssl's own Sign, so the cross-check does not lean on
// openssl's own hashing being correct) with openssl's SignDigest, then
// verifies with software's independent VerifyDigest — a real cross-check
// that SignDigest signs the given bytes as-is, over every advertised curve,
// both signature formats, and both an explicit and an inferred
// (UNSPECIFIED) hash algorithm.
func TestSignDigest_ECDSA_verifiesWithSoftware(t *testing.T) {
	message := []byte("sign this digest with openssl, verify with software")
	sha256Digest := sha256.Sum256(message)
	sha384Digest := sha512.Sum384(message)
	sha512Digest := sha512.Sum512(message)

	tests := []struct {
		name   string
		alg    *types.AlgorithmDetails
		digest []byte
		hash   types.HashAlgorithm
	}{
		{"p256-der-explicit-hash", ecdsaP256Details(), sha256Digest[:], types.HashAlgorithm_HASH_ALGORITHM_SHA256},
		{"p256-der-unspecified-hash", ecdsaP256Details(), sha256Digest[:], types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED},
		{"p384-der", ecdsaP384Details(), sha384Digest[:], types.HashAlgorithm_HASH_ALGORITHM_SHA384},
		{"p521-der", ecdsaP521Details(), sha512Digest[:], types.HashAlgorithm_HASH_ALGORITHM_SHA512},
		{"p256-p1363", ecdsaP256P1363Details(), sha256Digest[:], types.HashAlgorithm_HASH_ALGORITHM_SHA256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			p, err := openssl.New(ctx)
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetKeyMaterial(),
				KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
				Digest:              tt.digest,
				HashAlgorithm:       tt.hash,
			})
			if err != nil {
				t.Fatalf("SignDigest: %v", err)
			}

			sw := software.New()
			verifyResp, err := sw.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetPublicKeyBytes(),
				KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
				Digest:              tt.digest,
				Signature:           signResp.GetSignature(),
				HashAlgorithm:       tt.hash,
			})
			if err != nil {
				t.Fatalf("software VerifyDigest: %v", err)
			}
			if !verifyResp.GetValid() {
				t.Error("software rejected a digest signature openssl produced")
			}
		})
	}
}

// TestSignDigest_ECDSA_curveMismatch is the negative control for
// checkCurveMatches on the SignDigest path.
func TestSignDigest_ECDSA_curveMismatch(t *testing.T) {
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
	_, err = p.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           ecdsaP384Details(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              digest[:],
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a P-256 key declared as P-384, got: %v", err)
	}
}

// TestSignDigest_ECDSA_unspecifiedHashUninferableLength is the negative
// control for ecdsaDigestSignName's inference fallback: a digest whose
// length matches none of SHA-256/384/512 and declares no hash_algorithm
// cannot be resolved to a concrete digest name, and must be rejected rather
// than silently guessed at.
func TestSignDigest_ECDSA_unspecifiedHashUninferableLength(t *testing.T) {
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

	_, err = p.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           ecdsaP256Details(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              make([]byte, 20), // SHA-1-shaped; SHA-1 is not one of the inferable sizes
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED,
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for an unresolvable 20-byte digest, got: %v", err)
	}
}

// TestSignDigest_RSA_verifiesWithSoftware mirrors the ECDSA cross-check for
// RSA-PSS and RSA-PKCS1v15.
func TestSignDigest_RSA_verifiesWithSoftware(t *testing.T) {
	message := []byte("sign this digest with openssl, verify with software")
	digest := sha256.Sum256(message)

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
			p, err := openssl.New(ctx)
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetKeyMaterial(),
				KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
				Digest:              digest[:],
				HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			})
			if err != nil {
				t.Fatalf("SignDigest: %v", err)
			}

			sw := software.New()
			verifyResp, err := sw.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetPublicKeyBytes(),
				KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
				Digest:              digest[:],
				Signature:           signResp.GetSignature(),
				HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			})
			if err != nil {
				t.Fatalf("software VerifyDigest: %v", err)
			}
			if !verifyResp.GetValid() {
				t.Error("software rejected a digest signature openssl produced")
			}
		})
	}
}

// TestSignDigest_RSA_keySizeMismatch is the negative control for
// checkRSAKeySize on the SignDigest path.
func TestSignDigest_RSA_keySizeMismatch(t *testing.T) {
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
	_, err = p.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           rsaPssDetails(3072),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              digest[:],
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a 2048-bit key declared as 3072-bit, got: %v", err)
	}
}

// TestSignDigest_Ed25519PH_verifiesWithSoftware cross-checks Ed25519ph — the
// one algorithm where SignDigest genuinely needs the raw EVP_PKEY_sign entry
// point (see signEd25519PHDigest's doc comment): a caller-computed SHA-512
// digest, signed by openssl's SignDigest, verified by software's
// independent VerifyDigest.
func TestSignDigest_Ed25519PH_verifiesWithSoftware(t *testing.T) {
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

	digest := sha512.Sum512([]byte("sign this digest with openssl (ph), verify with software"))
	signResp, err := p.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           ed25519phDetails(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              digest[:],
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA512,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	sw := software.New()
	verifyResp, err := sw.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		Algorithm:           ed25519phDetails(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Digest:              digest[:],
		Signature:           signResp.GetSignature(),
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA512,
	})
	if err != nil {
		t.Fatalf("software VerifyDigest: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("software rejected a digest signature openssl produced")
	}
}

// ed25519PureExplicitDetails is ed25519Details with an explicit PURE
// variant, as distinct from the UNSPECIFIED zero value: SignDigest's
// variant check (mirrored from software.DigestSign) only rejects a variant
// that is neither UNSPECIFIED nor PH, so UNSPECIFIED itself passes through
// unrejected — a pre-existing gap in that check, inherited here rather than
// introduced by it. Explicit PURE is the part of the rejection this test can
// actually exercise.
func ed25519PureExplicitDetails() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ed25519{
			Ed25519: &types.Ed25519Params{Variant: types.Ed25519Variant_ED25519_VARIANT_PURE},
		},
	}
}

// TestSignDigest_Ed25519_pureVariantRejected is the negative control proving
// SignDigest rejects an explicitly-declared pure Ed25519 — only ph is
// prehashable.
func TestSignDigest_Ed25519_pureVariantRejected(t *testing.T) {
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
	_, err = p.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           ed25519PureExplicitDetails(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              digest[:],
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA512,
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for pure Ed25519 (not prehashable), got: %v", err)
	}
}

// TestSignDigest_Ed25519PH_wrongHashRejected is the negative control for
// checkEd25519PHHash: RFC 8032 fixes Ed25519ph's prehash to SHA-512, so a
// caller declaring a different 64-byte-digest hash (SHA3-512 here) must be
// rejected rather than silently accepted just because the length matches.
func TestSignDigest_Ed25519PH_wrongHashRejected(t *testing.T) {
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
	_, err = p.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           ed25519phDetails(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              digest[:],
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA3_512,
	})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for a non-SHA-512 declared hash, got: %v", err)
	}
}

// TestSignDigest_MLDSA_rejected proves ML-DSA is rejected outright: FIPS 204
// has no raw-digest form for ML-DSA in OpenSSL either (see
// ossl.Key.SignDigest's doc comment), matching software's identical
// rejection exactly, including the error code.
func TestSignDigest_MLDSA_rejected(t *testing.T) {
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
	_, err = p.SignDigest(ctx, &providerpb.SignDigestRequest{
		Algorithm:           mlDSADetails(types.MlDsaParameterSet_ML_DSA_65),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Digest:              digest[:],
		HashAlgorithm:       types.HashAlgorithm_HASH_ALGORITHM_SHA256,
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for ML-DSA (not prehashable), got: %v", err)
	}
}
