package openssl_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

func ed25519Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ed25519{Ed25519: &types.Ed25519Params{}},
	}
}

func TestGenerateKey_Ed25519_happyPath(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: ed25519Details()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
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
	if _, ok := privAny.(ed25519.PrivateKey); !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", privAny)
	}

	pubAny, err := x509.ParsePKIXPublicKey(resp.GetPublicKeyBytes())
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	if _, ok := pubAny.(ed25519.PublicKey); !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", pubAny)
	}
}

func TestGenerateKey_Ed25519_keysAreUnique(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	r1, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ed25519Details()})
	if err != nil {
		t.Fatalf("GenerateKey (1st): %v", err)
	}
	r2, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ed25519Details()})
	if err != nil {
		t.Fatalf("GenerateKey (2nd): %v", err)
	}

	if string(r1.GetPublicKeyBytes()) == string(r2.GetPublicKeyBytes()) {
		t.Error("two generated keys should not be identical")
	}
}

// TestGenerateKey_Ed25519_crossProviderInterop is the interop check the
// plan requires (I7), mirroring ecdsa_test.go's and rsa_test.go's: proves
// openssl's PKCS#8/SPKI material parses under software's stdlib parsers and
// vice versa, in both directions, rather than assuming it from the
// encoding labels agreeing.
func TestGenerateKey_Ed25519_crossProviderInterop(t *testing.T) {
	ctx := context.Background()

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	osslResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ed25519Details()})
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
	swResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ed25519Details()})
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
