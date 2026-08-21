package openssl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

func ecdsaP384Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{
				Curve: types.EllipticCurve_ELLIPTIC_CURVE_P384,
				Hash:  types.HashAlgorithm_HASH_ALGORITHM_SHA384,
			},
		},
	}
}

func ecdsaP521Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{
				Curve: types.EllipticCurve_ELLIPTIC_CURVE_P521,
				Hash:  types.HashAlgorithm_HASH_ALGORITHM_SHA512,
			},
		},
	}
}

func ecdsaP256P1363Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{
				Curve:           types.EllipticCurve_ELLIPTIC_CURVE_P256,
				Hash:            types.HashAlgorithm_HASH_ALGORITHM_SHA256,
				SignatureFormat: types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363,
			},
		},
	}
}

func TestGenerateKey_ECDSA_happyPath(t *testing.T) {
	tests := []struct {
		name      string
		alg       *types.AlgorithmDetails
		wantCurve elliptic.Curve
	}{
		{"p256", ecdsaP256Details(), elliptic.P256()},
		{"p384", ecdsaP384Details(), elliptic.P384()},
		{"p521", ecdsaP521Details(), elliptic.P521()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := openssl.New(context.Background())
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			checkECDSAGenerateKeyResponse(t, resp, tt.wantCurve)
		})
	}
}

// checkECDSAGenerateKeyResponse asserts the shape TestGenerateKey_ECDSA_happyPath
// expects from every curve: non-empty material, the declared SEC1/SPKI
// encodings, and — since a label alone proves nothing — that the stdlib
// parsers those encodings promise actually accept the bytes and agree on
// the curve.
func checkECDSAGenerateKeyResponse(t *testing.T, resp *providerpb.GenerateKeyResponse, wantCurve elliptic.Curve) {
	t.Helper()

	if len(resp.GetPublicKeyBytes()) == 0 {
		t.Error("expected non-empty public key bytes")
	}
	if len(resp.GetKeyMaterial()) == 0 {
		t.Error("expected non-empty key material")
	}
	if got := resp.GetKeyMaterialEncoding(); got != providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1 {
		t.Errorf("KeyMaterialEncoding: got %v want SEC1", got)
	}
	if got := resp.GetPublicKeyEncoding(); got != providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI {
		t.Errorf("PublicKeyEncoding: got %v want SPKI", got)
	}

	priv, err := x509.ParseECPrivateKey(resp.GetKeyMaterial())
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}
	if priv.Curve != wantCurve {
		t.Errorf("private key curve: got %s want %s", priv.Curve.Params().Name, wantCurve.Params().Name)
	}

	pubAny, err := x509.ParsePKIXPublicKey(resp.GetPublicKeyBytes())
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pubAny)
	}
	if pub.Curve != wantCurve {
		t.Errorf("public key curve: got %s want %s", pub.Curve.Params().Name, wantCurve.Params().Name)
	}
}

func TestGenerateKey_ECDSA_keysAreUnique(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	r1, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})
	if err != nil {
		t.Fatalf("GenerateKey (1st): %v", err)
	}
	r2, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})
	if err != nil {
		t.Fatalf("GenerateKey (2nd): %v", err)
	}

	if string(r1.GetPublicKeyBytes()) == string(r2.GetPublicKeyBytes()) {
		t.Error("two generated keys should not be identical")
	}
}

// TestGenerateKey_ECDSA_crossProviderInterop is the interop check between
// software and openssl provider. Openssl's SEC1/SPKI encodings match
// software's is proven here by actually parsing material across providers,
// not assumed from the encoding labels agreeing.
func TestGenerateKey_ECDSA_crossProviderInterop(t *testing.T) {
	ctx := context.Background()

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	// Direction 1: openssl-generated material parses with the stdlib
	// parsers software's own provider uses.
	osslResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})
	if err != nil {
		t.Fatalf("openssl GenerateKey: %v", err)
	}
	if _, parseErr := x509.ParseECPrivateKey(osslResp.GetKeyMaterial()); parseErr != nil {
		t.Errorf("stdlib x509.ParseECPrivateKey could not parse openssl-generated SEC1 material: %v", parseErr)
	}
	if _, parseErr := x509.ParsePKIXPublicKey(osslResp.GetPublicKeyBytes()); parseErr != nil {
		t.Errorf("stdlib x509.ParsePKIXPublicKey could not parse openssl-generated SPKI material: %v", parseErr)
	}

	// Direction 2: software-generated material parses with ossl-go's
	// parsers -- the direction this provider's own Sign/Verify will need
	// once they exist.
	sw := software.New()
	swResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})
	if err != nil {
		t.Fatalf("software GenerateKey: %v", err)
	}

	libctx, err := ossl.NewContext()
	if err != nil {
		t.Fatalf("ossl.NewContext: %v", err)
	}
	defer libctx.Close()

	privKey, err := libctx.ParseSEC1PrivateKey(swResp.GetKeyMaterial())
	if err != nil {
		t.Fatalf("ossl-go ParseSEC1PrivateKey could not parse software-generated SEC1 material: %v", err)
	}
	defer privKey.Close()

	pubKey, err := libctx.ParseSPKIPublicKey(swResp.GetPublicKeyBytes())
	if err != nil {
		t.Fatalf("ossl-go ParseSPKIPublicKey could not parse software-generated SPKI material: %v", err)
	}
	defer pubKey.Close()
}

// TestSign_ECDSA_verifiesWithSoftware is the sign-side cross-check the plan
// requires: sign with openssl, then verify with software's independent
// implementation, over every advertised curve and both signature formats --
// proving the signature is genuinely valid, not just that Sign returned
// without an error.
func TestSign_ECDSA_verifiesWithSoftware(t *testing.T) {
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
			p, err := openssl.New(ctx)
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			message := []byte("sign with openssl, verify with software")
			signResp, err := p.Sign(ctx, &providerpb.SignRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetKeyMaterial(),
				KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
				Input:               message,
				ScopeParams:         signRequestNoContext(),
			})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			sw := software.New()
			verifyResp, err := sw.Verify(ctx, &providerpb.VerifyRequest{
				Algorithm:           tt.alg,
				KeyMaterial:         keyResp.GetPublicKeyBytes(),
				KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
				Input:               message,
				Signature:           signResp.GetSignature(),
				ScopeParams:         verifyRequestNoContext(),
			})
			if err != nil {
				t.Fatalf("software Verify: %v", err)
			}
			if !verifyResp.GetValid() {
				t.Error("software rejected a signature openssl produced")
			}
		})
	}
}

// TestSign_ECDSA_softwareRejectsTamperedMessage is the negative control for
// the cross-check above: verifying a genuinely different message against
// the same signature must fail, proving the cross-check can actually catch
// a bad signature rather than always reporting success.
func TestSign_ECDSA_softwareRejectsTamperedMessage(t *testing.T) {
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

	sw := software.New()
	verifyResp, err := sw.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           ecdsaP256Details(),
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               []byte("a different message"),
		Signature:           signResp.GetSignature(),
		ScopeParams:         verifyRequestNoContext(),
	})
	if err != nil {
		t.Fatalf("software Verify: %v", err)
	}
	if verifyResp.GetValid() {
		t.Error("software accepted a signature over a message it was never computed for")
	}
}

// TestSign_ECDSA_curveMismatch is the negative control for checkCurveMatches:
// signing a P-256 key while declaring P-384 must be rejected with
// CodeInvalidArgument rather than silently signing under whichever curve
// the stored key actually is.
func TestSign_ECDSA_curveMismatch(t *testing.T) {
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

	_, err = p.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           ecdsaP384Details(),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               []byte("message"),
		ScopeParams:         signRequestNoContext(),
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a P-256 key declared as P-384, got: %v", err)
	}
}
