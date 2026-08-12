package software_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	api "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider"
	"github.com/agile-crypto/citius-server/internal/provider/software"
	"google.golang.org/protobuf/encoding/protojson"
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

func TestProvider_SupportedAlgorithms_hasKeyAlgorithms(t *testing.T) {
	p := software.New()
	algs := p.SupportedAlgorithms()

	ids := make(map[string]bool)
	for _, id := range algs {
		ids[id] = true
	}

	// A representative sample across every family SupportedAlgorithms
	// advertises — not exhaustive (see
	// TestProvider_SupportedAlgorithms_everyEntryMatchesCatalogAndDispatches
	// for exhaustive, dispatch-verified coverage).
	for _, want := range []string{
		"ecdsa-p256-sha256-der", "ecdsa-p384-sha384-der", "ecdsa-p521-sha512-der",
		"rsa-pss-sha256-mgf1-32-2048", "rsa-pkcs1v15-sha256-2048",
		"ed25519", "ed25519ph",
		"ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
		"aes-128-gcm-128-96", "aes-256-gcm-128-96",
	} {
		if !ids[want] {
			t.Errorf("missing %s from SupportedAlgorithms", want)
		}
	}
}

// standardCatalogPath returns the absolute path to the standard_algorithms.json
// catalog, mirroring the identically-named helper in internal/template's own
// tests (that package's helper is unexported and this one lives in a
// different package, so it cannot be reused directly).
func standardCatalogPath() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "proto", "standard_algorithms.json")
}

// TestProvider_SupportedAlgorithms_everyEntryMatchesCatalogAndDispatches is
// the regression guard for the SupportedAlgorithms/dispatch-switch
// consistency bug: every template ID this provider advertises must (a)
// exist in the real production catalog and (b) actually succeed at
// GenerateKey via the real provider, not just compile. Before this test
// existed, provider.Registry.MatchForTemplate could route CreateKey to this
// provider for a template whose algorithm the dispatch switches didn't
// actually implement — or the reverse, silently blocking CreateKey for an
// algorithm that fully works once a key exists.
func TestProvider_SupportedAlgorithms_everyEntryMatchesCatalogAndDispatches(t *testing.T) {
	data, err := os.ReadFile(standardCatalogPath())
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	ctx := context.Background()
	// Parse the catalog proto-JSON directly rather than via
	// internal/template.ParseStandardCatalog: this test package
	// (internal/provider/software) is not allowed to import internal/template
	// (sibling bounded contexts, enforced by depguard), and this is the same
	// protojson.Unmarshal call that function itself makes.
	catalog := &api.StandardAlgorithmCatalog{}
	if err = protojson.Unmarshal(data, catalog); err != nil {
		t.Fatalf("protojson.Unmarshal catalog: %v", err)
	}
	templates := catalog.GetTemplates()

	p := software.New()
	for _, id := range p.SupportedAlgorithms() {
		tmpl, ok := templates[id]
		if !ok {
			t.Errorf("%s: advertised in SupportedAlgorithms but not found in the standard catalog", id)
			continue
		}
		if _, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: tmpl.GetAlgorithm()}); err != nil {
			t.Errorf("%s: advertised in SupportedAlgorithms but GenerateKey failed: %v", id, err)
		}
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
