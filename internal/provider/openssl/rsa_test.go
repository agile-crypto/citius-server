package openssl_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

func rsaPssDetails(bits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_RsaPss{
			RsaPss: &types.RsaPssParams{KeySizeBits: bits},
		},
	}
}

func rsaPkcs1v15Details(bits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_RsaPkcs1V15{
			RsaPkcs1V15: &types.RsaPkcs1V15Params{KeySizeBits: bits},
		},
	}
}

func TestGenerateKey_RSA_happyPath(t *testing.T) {
	tests := []struct {
		name     string
		alg      *types.AlgorithmDetails
		wantBits int
	}{
		{"pss-2048", rsaPssDetails(2048), 2048},
		{"pss-3072", rsaPssDetails(3072), 3072},
		{"pss-4096", rsaPssDetails(4096), 4096},
		{"pkcs1v15-2048", rsaPkcs1v15Details(2048), 2048},
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
			checkRSAGenerateKeyResponse(t, resp, tt.wantBits)
		})
	}
}

// checkRSAGenerateKeyResponse asserts the shape every RSA family (PSS or
// PKCS#1 v1.5) shares: non-empty material, the declared PKCS#8/SPKI
// encodings, and that the stdlib parsers those encodings promise actually
// accept the bytes and agree on the modulus size.
func checkRSAGenerateKeyResponse(t *testing.T, resp *providerpb.GenerateKeyResponse, wantBits int) {
	t.Helper()

	if len(resp.GetPublicKeyBytes()) == 0 {
		t.Error("expected non-empty public key bytes")
	}
	if len(resp.GetKeyMaterial()) == 0 {
		t.Error("expected non-empty key material")
	}
	if got := resp.GetKeyMaterialEncoding(); got != providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8 {
		t.Errorf("KeyMaterialEncoding: got %v want PKCS8", got)
	}
	if got := resp.GetPublicKeyEncoding(); got != providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI {
		t.Errorf("PublicKeyEncoding: got %v want SPKI", got)
	}

	privAny, err := x509.ParsePKCS8PrivateKey(resp.GetKeyMaterial())
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	priv, ok := privAny.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", privAny)
	}
	if priv.N.BitLen() != wantBits {
		t.Errorf("private key modulus: got %d bits want %d", priv.N.BitLen(), wantBits)
	}

	pubAny, err := x509.ParsePKIXPublicKey(resp.GetPublicKeyBytes())
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pubAny)
	}
	if pub.N.BitLen() != wantBits {
		t.Errorf("public key modulus: got %d bits want %d", pub.N.BitLen(), wantBits)
	}
}

func TestGenerateKey_RSA_keysAreUnique(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	r1, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: rsaPssDetails(2048)})
	if err != nil {
		t.Fatalf("GenerateKey (1st): %v", err)
	}
	r2, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: rsaPssDetails(2048)})
	if err != nil {
		t.Fatalf("GenerateKey (2nd): %v", err)
	}

	if string(r1.GetPublicKeyBytes()) == string(r2.GetPublicKeyBytes()) {
		t.Error("two generated keys should not be identical")
	}
}

// TestGenerateKey_RSA_crossProviderInterop is the interop check the plan
// requires (I7), mirroring ecdsa_test.go's: proves openssl's PKCS#8/SPKI
// material parses under software's stdlib parsers and vice versa, in both
// directions, rather than assuming it from the encoding labels agreeing.
func TestGenerateKey_RSA_crossProviderInterop(t *testing.T) {
	ctx := context.Background()

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	osslResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: rsaPssDetails(2048)})
	if err != nil {
		t.Fatalf("openssl GenerateKey: %v", err)
	}
	if _, parseErr := x509.ParsePKCS8PrivateKey(osslResp.GetKeyMaterial()); parseErr != nil {
		t.Errorf("stdlib x509.ParsePKCS8PrivateKey could not parse openssl-generated PKCS8 material: %v", parseErr)
	}
	if _, parseErr := x509.ParsePKIXPublicKey(osslResp.GetPublicKeyBytes()); parseErr != nil {
		t.Errorf("stdlib x509.ParsePKIXPublicKey could not parse openssl-generated SPKI material: %v", parseErr)
	}

	sw := software.New()
	swResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: rsaPssDetails(2048)})
	if err != nil {
		t.Fatalf("software GenerateKey: %v", err)
	}

	libctx, err := ossl.NewContext()
	if err != nil {
		t.Fatalf("ossl.NewContext: %v", err)
	}
	defer libctx.Close()

	privKey, err := libctx.ParsePKCS8PrivateKey(swResp.GetKeyMaterial())
	if err != nil {
		t.Fatalf("ossl-go ParsePKCS8PrivateKey could not parse software-generated PKCS8 material: %v", err)
	}
	defer privKey.Close()

	pubKey, err := libctx.ParseSPKIPublicKey(swResp.GetPublicKeyBytes())
	if err != nil {
		t.Fatalf("ossl-go ParseSPKIPublicKey could not parse software-generated SPKI material: %v", err)
	}
	defer pubKey.Close()
}

// TestSign_RSA_verifiesWithSoftware is the sign-side cross-check the plan
// requires: sign with openssl, then verify with software's independent
// implementation, over PSS (default SHA-256, and explicit SHA-384) and
// PKCS#1 v1.5 -- proving the signature is genuinely valid, not just that
// Sign returned without an error.
func TestSign_RSA_verifiesWithSoftware(t *testing.T) {
	rsaPss4096SHA384Details := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_RsaPss{
			RsaPss: &types.RsaPssParams{KeySizeBits: 4096, Hash: types.HashAlgorithm_HASH_ALGORITHM_SHA384},
		},
	}
	tests := []struct {
		name string
		alg  *types.AlgorithmDetails
	}{
		{"pss-2048-sha256", rsaPssDetails(2048)},
		{"pss-4096-sha384", rsaPss4096SHA384Details},
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

// TestSign_RSA_keySizeMismatch is the negative control for checkRSAKeySize:
// signing a 2048-bit key while declaring 3072 bits must be rejected with
// CodeInvalidArgument rather than silently signing under whichever size the
// stored key actually is.
func TestSign_RSA_keySizeMismatch(t *testing.T) {
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

	_, err = p.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           rsaPssDetails(3072),
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               []byte("message"),
		ScopeParams:         signRequestNoContext(),
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a 2048-bit key declared as 3072-bit, got: %v", err)
	}
}
