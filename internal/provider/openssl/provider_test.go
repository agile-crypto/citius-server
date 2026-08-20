package openssl_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
)

// Compile-time assertion: Provider implements provider.Backend.
var _ provider.Backend = (*openssl.Provider)(nil)

func ecdsaP256Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{
				Curve: types.EllipticCurve_ELLIPTIC_CURVE_P256,
				Hash:  types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			},
		},
	}
}

// ============================================================================
// Constructor tests
// ============================================================================

func TestNew_defaultName(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	if got := p.Name(); got != "openssl" {
		t.Errorf("Name: got %q want %q", got, "openssl")
	}
	if got := p.Type(); got != "openssl" {
		t.Errorf("Type: got %q want %q", got, "openssl")
	}
}

func TestNew_withName(t *testing.T) {
	p, err := openssl.New(context.Background(), openssl.WithName("openssl-fips"))
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	if got := p.Name(); got != "openssl-fips" {
		t.Errorf("Name: got %q want %q", got, "openssl-fips")
	}
	// Type stays "openssl" regardless of mode — Name is what distinguishes instances.
	if got := p.Type(); got != "openssl" {
		t.Errorf("Type: got %q want %q", got, "openssl")
	}
}

// TestNew_multipleInstances_independentLifecycle proves two named instances
// are independently constructible and closeable: closing one instance must
// not break the other's Backend surface.
//
// GenerateKey now performs a real EVP_PKEY_generate through libctx (ECDSA
// landed), so a successful key generation on p2 after p1.Close is a genuine
// exercise of p2's own, independent context — not just its
// request-validation path, which is all this test could prove before any
// real operation existed.
func TestNew_multipleInstances_independentLifecycle(t *testing.T) {
	p1, err := openssl.New(context.Background(), openssl.WithName("a"))
	if err != nil {
		t.Fatalf("openssl.New(a): %v", err)
	}
	p2, err := openssl.New(context.Background(), openssl.WithName("b"))
	if err != nil {
		t.Fatalf("openssl.New(b): %v", err)
	}
	defer p2.Close()

	if closeErr := p1.Close(); closeErr != nil {
		t.Fatalf("p1.Close: %v", closeErr)
	}

	resp, err := p2.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})
	if err != nil {
		t.Fatalf("GenerateKey on p2 after p1.Close: %v", err)
	}
	if len(resp.GetKeyMaterial()) == 0 || len(resp.GetPublicKeyBytes()) == 0 {
		t.Errorf("expected non-empty key material and public key bytes, got %+v", resp)
	}
}

func TestProvider_Close_idempotent(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// ============================================================================
// Backend stub tests
// ============================================================================

// TestProvider_GenerateKey_notImplemented uses AES-GCM rather than ECDSA:
// symmetric key generation is a separate, later commit, so this arm still
// falls through GenerateKey's dispatch to the default case. ECDSA moved to
// ecdsa_test.go once it stopped being a stub.
func TestProvider_GenerateKey_notImplemented(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	req := &providerpb.GenerateKeyRequest{
		Algorithm: &types.AlgorithmDetails{
			Algorithm: &types.AlgorithmDetails_AesGcm{
				AesGcm: &types.AesGcmParams{KeySizeBits: 256, IvSizeBits: 96, TagSizeBits: 128},
			},
		},
	}
	_, err = p.GenerateKey(context.Background(), req)
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// TestProvider_GenerateKey_validatesBeforeStub is the negative control for
// the validate-then-dispatch shape: an invalid request (no Algorithm) must
// fail with CodeInvalidArgument, not the stub's CodeNotImplemented — proving
// validateRequest genuinely runs first rather than the stub swallowing every
// input into the same error.
func TestProvider_GenerateKey_validatesBeforeStub(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	_, err = p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for missing algorithm, got: %v", err)
	}
}

func TestProvider_DestroyKey_notImplemented(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	_, err = p.DestroyKey(context.Background(), &providerpb.DestroyKeyRequest{})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

func TestProvider_ExportPublicKey_notImplemented(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	_, err = p.ExportPublicKey(context.Background(), &providerpb.ExportPublicKeyRequest{})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

// ============================================================================
// Capability tests
// ============================================================================

// TestProvider_SupportedAlgorithms_includesAllAsymmetric documents the
// current state: catalog has exactly the entries every asymmetric key
// family added so far (ECDSA, RSA, Ed25519, ML-DSA), nothing more
// (symmetric is still a later commit). This test is meant to start failing
// the moment the next entry lands — that failure is the signal to update
// it, not a regression.
func TestProvider_SupportedAlgorithms_includesAllAsymmetric(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	want := map[string]bool{
		"ecdsa-p256-sha256-der":       true,
		"ecdsa-p384-sha384-der":       true,
		"ecdsa-p521-sha512-der":       true,
		"rsa-pss-sha256-mgf1-32-2048": true,
		"rsa-pss-sha256-mgf1-32-3072": true,
		"rsa-pss-sha384-mgf1-48-4096": true,
		"rsa-pkcs1v15-sha256-2048":    true,
		"ed25519":                     true,
		"ed25519ph":                   true,
		"ml-dsa-44":                   true,
		"ml-dsa-65":                   true,
		"ml-dsa-87":                   true,
	}
	got := p.SupportedAlgorithms()
	if len(got) != len(want) {
		t.Fatalf("SupportedAlgorithms: got %v, want exactly %d entries", got, len(want))
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected algorithm %q in SupportedAlgorithms", id)
		}
	}
}

// TestProvider_VerifyCapabilities_allAsymmetric proves VerifyCapabilities
// performs real key generation, sign, and verify for every advertised
// capability (ossl.Context.VerifyCapability), not just the structural
// Supports check SupportedAlgorithms relies on. The RSA entries' trial
// exercises PSS specifically, including the PKCS#1 v1.5 entry — see the
// caveat on catalog's RSA entries in capability.go.
func TestProvider_VerifyCapabilities_allAsymmetric(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	if err := p.VerifyCapabilities(context.Background()); err != nil {
		t.Errorf("VerifyCapabilities: %v", err)
	}
}
