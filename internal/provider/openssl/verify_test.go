package openssl_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

// TestVerify_notImplemented probes Verify's dispatch default case: every
// real algorithm arm now has a case (ECDSA, RSA-PSS, RSA-PKCS1v15, Ed25519,
// ML-DSA), so an AlgorithmDetails whose oneof is present but empty is the
// only shape left that still reaches default.
func TestVerify_notImplemented(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	_, err = p.Verify(context.Background(), &providerpb.VerifyRequest{
		Algorithm:   &types.AlgorithmDetails{},
		KeyMaterial: []byte("placeholder"),
		Input:       []byte("message"),
		Signature:   []byte("sig"),
		ScopeParams: verifyRequestNoContext(),
	})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// TestVerify_validatesBeforeStub is the negative control for the
// validate-then-dispatch shape: a request missing Algorithm entirely must
// fail with CodeInvalidArgument, not CodeNotImplemented.
func TestVerify_validatesBeforeStub(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	_, err = p.Verify(context.Background(), &providerpb.VerifyRequest{})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for missing algorithm, got: %v", err)
	}
}

// TestVerify_ECDSA_verifiesSoftwareSignature completes the bidirectional
// interop check C9 started: C9 proved openssl-signed material verifies with
// software; this proves the reverse -- a signature software produced
// verifies with openssl's own Verify.
func TestVerify_ECDSA_verifiesSoftwareSignature(t *testing.T) {
	tests := []struct {
		name string
		alg  *types.AlgorithmDetails
	}{
		{"p256-der", ecdsaP256Details()},
		{"p384-der", ecdsaP384Details()},
		{"p521-der", ecdsaP521Details()},
		{"p256-p1363", ecdsaP256P1363Details()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			sw := software.New()

			keyResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("software GenerateKey: %v", err)
			}

			message := []byte("sign with software, verify with openssl")
			signResp, err := sw.Sign(ctx, &providerpb.SignRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetKeyMaterial(),
				KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
				Input:               message,
				ScopeParams:         signRequestNoContext(),
			})
			if err != nil {
				t.Fatalf("software Sign: %v", err)
			}

			p, err := openssl.New(ctx)
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			verifyResp, err := p.Verify(ctx, &providerpb.VerifyRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetPublicKeyBytes(),
				KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
				Input:               message,
				Signature:           signResp.GetSignature(),
				ScopeParams:         verifyRequestNoContext(),
			})
			if err != nil {
				t.Fatalf("openssl Verify: %v", err)
			}
			if !verifyResp.GetValid() {
				t.Error("openssl rejected a signature software produced")
			}
		})
	}
}

// TestVerify_ECDSA_rejectsTamperedSignature is the negative control: a
// well-formed but wrong signature (a genuinely different payload signed)
// must come back valid=false with no error -- not an error return.
func TestVerify_ECDSA_rejectsTamperedSignature(t *testing.T) {
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
	signResp, err := p.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           ecdsaP256Details(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               []byte("the original message"),
		ScopeParams:         signRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResp, err := p.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           ecdsaP256Details(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               []byte("a different message"),
		Signature:           signResp.GetSignature(),
		ScopeParams:         verifyRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("Verify returned an error for a wrong signature, want valid=false: %v", err)
	}
	if verifyResp.GetValid() {
		t.Error("openssl accepted a signature over a message it was never computed for")
	}
}

// TestVerify_ECDSA_rejectsMalformedSignatureBytes is the negative control
// for the other half of the plan's requirement: signature bytes that are
// not even well-formed DER must still come back valid=false with no error,
// not a hard failure -- ossl-go's Key.Verify collapses this into
// ErrVerification itself (see verifyOutcome's doc comment).
func TestVerify_ECDSA_rejectsMalformedSignatureBytes(t *testing.T) {
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

	verifyResp, err := p.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           ecdsaP256Details(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               []byte("message"),
		Signature:           []byte("not a valid DER signature at all"),
		ScopeParams:         verifyRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("Verify returned an error for malformed signature bytes, want valid=false: %v", err)
	}
	if verifyResp.GetValid() {
		t.Error("openssl accepted garbage bytes as a valid signature")
	}
}

// TestVerify_ECDSA_curveMismatch is the negative control for checkCurveMatches
// reused on the verify path.
func TestVerify_ECDSA_curveMismatch(t *testing.T) {
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
	signResp, err := p.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           ecdsaP256Details(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               []byte("message"),
		ScopeParams:         signRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	_, err = p.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           ecdsaP384Details(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               []byte("message"),
		Signature:           signResp.GetSignature(),
		ScopeParams:         verifyRequestNoContext(),
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a P-256 key declared as P-384, got: %v", err)
	}
}

// TestVerify_ECDSA_unsupportedFormatSurfacesAsError proves the plan's other
// required distinction: an unsupported *format* is a real configuration
// error, not a false-flagged verification -- unlike a bad signature, which
// never produces an error.
func TestVerify_ECDSA_unsupportedFormatSurfacesAsError(t *testing.T) {
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

	unsupportedFormat := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{
				Curve:           types.EllipticCurve_ELLIPTIC_CURVE_P256,
				Hash:            types.HashAlgorithm_HASH_ALGORITHM_SHA256,
				SignatureFormat: types.SignatureFormat_SIGNATURE_FORMAT_RAW,
			},
		},
	}
	_, err = p.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           unsupportedFormat,
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               []byte("message"),
		Signature:           []byte("irrelevant"),
		ScopeParams:         verifyRequestNoContext(),
	})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for SIGNATURE_FORMAT_RAW on ECDSA, got: %v", err)
	}
}

// TestVerify_RSA_verifiesSoftwareSignature completes the RSA bidirectional
// interop check.
func TestVerify_RSA_verifiesSoftwareSignature(t *testing.T) {
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

			message := []byte("sign with software, verify with openssl")
			signResp, err := sw.Sign(ctx, &providerpb.SignRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetKeyMaterial(),
				KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
				Input:               message,
				ScopeParams:         signRequestNoContext(),
			})
			if err != nil {
				t.Fatalf("software Sign: %v", err)
			}

			p, err := openssl.New(ctx)
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			verifyResp, err := p.Verify(ctx, &providerpb.VerifyRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetPublicKeyBytes(),
				KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
				Input:               message,
				Signature:           signResp.GetSignature(),
				ScopeParams:         verifyRequestNoContext(),
			})
			if err != nil {
				t.Fatalf("openssl Verify: %v", err)
			}
			if !verifyResp.GetValid() {
				t.Error("openssl rejected a signature software produced")
			}
		})
	}
}

// TestVerify_RSA_rejectsTamperedSignature is the negative control for RSA.
func TestVerify_RSA_rejectsTamperedSignature(t *testing.T) {
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
	signResp, err := p.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           rsaPssDetails(2048),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               []byte("the original message"),
		ScopeParams:         signRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResp, err := p.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           rsaPssDetails(2048),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               []byte("a different message"),
		Signature:           signResp.GetSignature(),
		ScopeParams:         verifyRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("Verify returned an error for a wrong signature, want valid=false: %v", err)
	}
	if verifyResp.GetValid() {
		t.Error("openssl accepted a signature over a message it was never computed for")
	}
}

// TestVerify_Ed25519_verifiesSoftwareSignature completes the pure-Ed25519
// bidirectional interop check.
func TestVerify_Ed25519_verifiesSoftwareSignature(t *testing.T) {
	ctx := context.Background()
	sw := software.New()

	keyResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ed25519Details()})
	if err != nil {
		t.Fatalf("software GenerateKey: %v", err)
	}

	message := []byte("sign with software, verify with openssl")
	signResp, err := sw.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           ed25519Details(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               message,
		ScopeParams:         signRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("software Sign: %v", err)
	}

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	verifyResp, err := p.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           ed25519Details(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               message,
		Signature:           signResp.GetSignature(),
		ScopeParams:         verifyRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("openssl Verify: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("openssl rejected a signature software produced")
	}
}

// TestVerify_Ed25519PH_roundTrips proves openssl's Verify handles ph
// directly through the regular Verify call -- the deliberate divergence
// from software (which only reaches ph through VerifyDigest) that
// signEd25519/verifyEd25519's doc comments call out. Sign and Verify are
// different EVP entry points (EVP_DigestSignInit vs EVP_DigestVerifyInit),
// so this is a genuine round trip through two independent code paths, not a
// tautology.
func TestVerify_Ed25519PH_roundTrips(t *testing.T) {
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

	message := []byte("sign and verify ph, both through openssl")
	signResp, err := p.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           ed25519phDetails(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               message,
		ScopeParams:         signRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResp, err := p.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           ed25519phDetails(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               message,
		Signature:           signResp.GetSignature(),
		ScopeParams:         verifyRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("openssl's own Verify rejected a ph signature openssl's own Sign produced")
	}
}

// TestVerify_Ed25519_ctxVariantRejected is the negative control for
// checkEd25519VariantSupported reused on the verify path.
func TestVerify_Ed25519_ctxVariantRejected(t *testing.T) {
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

	ctxDetails := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ed25519{
			Ed25519: &types.Ed25519Params{Variant: types.Ed25519Variant_ED25519_VARIANT_CTX},
		},
	}
	_, err = p.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           ctxDetails,
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               []byte("message"),
		Signature:           []byte("irrelevant"),
		ScopeParams:         verifyRequestNoContext(),
	})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for Ed25519ctx, got: %v", err)
	}
}

// TestVerify_MLDSA_verifiesSoftwareSignature completes the ML-DSA
// bidirectional interop check.
func TestVerify_MLDSA_verifiesSoftwareSignature(t *testing.T) {
	ctx := context.Background()
	alg := mlDSADetails(types.MlDsaParameterSet_ML_DSA_65)
	sw := software.New()

	keyResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("software GenerateKey: %v", err)
	}

	message := []byte("sign with software, verify with openssl")
	signResp, err := sw.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           alg,
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               message,
		ScopeParams:         signRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("software Sign: %v", err)
	}

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	verifyResp, err := p.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           alg,
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               message,
		Signature:           signResp.GetSignature(),
		ScopeParams:         verifyRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("openssl Verify: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("openssl rejected a signature software produced")
	}
}

// TestVerify_MLDSA_honorsDomainContext proves domain context is genuinely
// threaded on the verify side, symmetric with Sign's
// TestSign_MLDSA_honorsDomainContext. Both halves matter: verifying with
// the *same* context the signature was made under must succeed -- proving
// Context is actually passed to Key.Verify rather than silently dropped,
// since a dropped Context would still fail this on a mismatched context (any
// wrong context looks the same as no context at all) but would wrongly
// break the matching case too, where a genuinely-threaded and a
// silently-ignored Context are otherwise indistinguishable.
func TestVerify_MLDSA_honorsDomainContext(t *testing.T) {
	ctx := context.Background()
	alg := mlDSADetails(types.MlDsaParameterSet_ML_DSA_65)

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	message := []byte("message signed under a specific domain context")
	domainContext := []byte("citius-test-context")
	signResp, err := p.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           alg,
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               message,
		ScopeParams:         signRequestDomainContext(domainContext),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	matchResp, err := p.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           alg,
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               message,
		Signature:           signResp.GetSignature(),
		ScopeParams:         verifyRequestDomainContext(domainContext),
	})
	if err != nil {
		t.Fatalf("Verify (matching context): %v", err)
	}
	if !matchResp.GetValid() {
		t.Error("openssl rejected a signature verified with the same domain context it was signed under")
	}

	mismatchResp, err := p.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           alg,
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               message,
		Signature:           signResp.GetSignature(),
		ScopeParams:         verifyRequestDomainContext([]byte("a-different-context")),
	})
	if err != nil {
		t.Fatalf("Verify (mismatched context): %v", err)
	}
	if mismatchResp.GetValid() {
		t.Error("openssl accepted a signature under a domain context it was never signed with")
	}
}
