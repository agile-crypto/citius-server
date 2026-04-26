package software_test

import (
	"context"
	"testing"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/provider/software"
)

// Compile-time assertion: Provider implements provider.Backend.
var _ provider.Backend = (*software.Provider)(nil)

// Compile-time assertion: Provider implements AlgorithmCapabilityProvider.
var _ provider.AlgorithmCapabilityProvider = (*software.Provider)(nil)

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNew_notNil(t *testing.T) {
	p := software.New()
	if p == nil {
		t.Fatal("software.New() returned nil")
	}
}

// ============================================================================
// Identity Tests
// ============================================================================

func TestProvider_Name(t *testing.T) {
	p := software.New()
	if got := p.Name(); got != "software" {
		t.Errorf("Name: got %q want %q", got, "software")
	}
}

func TestProvider_Type(t *testing.T) {
	p := software.New()
	if got := p.Type(); got != "software" {
		t.Errorf("Type: got %q want %q", got, "software")
	}
}

// ============================================================================
// SupportedAlgorithms Tests
// ============================================================================

func TestProvider_SupportedAlgorithms_hasBothAlgorithms(t *testing.T) {
	p := software.New()
	algs := p.SupportedAlgorithms()

	ids := make(map[string]bool)
	for _, id := range algs {
		ids[id] = true
	}

	// ECDSA-P256-SHA256-DER
	if !ids["ecdsa-p256-sha256-der"] {
		t.Fatal("missing ecdsa-p256-sha256-der algorithm")
	}

	// ML-DSA-65
	if !ids["ml-dsa-65"] {
		t.Fatal("missing ml-dsa-65 algorithm")
	}
}

// ============================================================================
// DestroyKey Tests (no-op for stateless provider)
// ============================================================================

func TestProvider_DestroyKey_noopReturnsNil(t *testing.T) {
	p := software.New()
	// DestroyKey is a no-op for stateless provider - always succeeds
	resp, err := p.DestroyKey(context.Background(), &providerpb.DestroyKeyRequest{KeyMaterial: []byte("any")})
	if err != nil {
		t.Errorf("DestroyKey: unexpected error: %v", err)
	}
	if resp == nil {
		t.Error("DestroyKey: expected non-nil response")
	}
}

// ============================================================================
// ExportPublicKey Tests
// ============================================================================

func TestProvider_ExportPublicKey_returnsNotImplemented(t *testing.T) {
	p := software.New()
	_, err := p.ExportPublicKey(context.Background(), &providerpb.ExportPublicKeyRequest{KeyMaterial: []byte("any")})
	if err == nil {
		t.Fatal("expected error from ExportPublicKey (stateless provider)")
	}
	// TODO: Stateless provider doesn't return keys for now - ExportPublicKey is not supported
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}
