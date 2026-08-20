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
// This does not yet exercise ossl.Context isolation itself (GenerateKey in
// this commit is a stub that never reads Provider.libctx) — that guarantee
// belongs to ossl-go and is proven meaningfully once a real operation runs
// per-context, starting with capability derivation. What this test does
// prove: Close on one instance cannot panic or corrupt package-level state
// (e.g. the shared protovalidate validator) that the other instance depends
// on.
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

	if err := p1.Close(); err != nil {
		t.Fatalf("p1.Close: %v", err)
	}

	if _, err := p2.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()}); !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented from p2 after p1.Close, got: %v", err)
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

func TestProvider_GenerateKey_notImplemented(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	_, err = p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})
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
