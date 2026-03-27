package provider_test

import (
	"context"
	"testing"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/provider"
)

// capableProvider is a stub ProviderInstance that supports a set of algorithm IDs.
type capableProvider struct {
	name       string
	algorithms []string // algorithm IDs this provider supports
}

func (c *capableProvider) Name() string { return c.name }
func (c *capableProvider) Type() string { return "stub" }
func (c *capableProvider) GenerateKey(_ context.Context, _ *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return nil, nil
}
func (c *capableProvider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return nil, nil
}
func (c *capableProvider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return nil, nil
}
func (c *capableProvider) Sign(_ context.Context, _ *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return nil, nil
}
func (c *capableProvider) Verify(_ context.Context, _ *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return nil, nil
}

// SupportedAlgorithms returns the algorithm IDs this provider handles.
// Used by MatchForTemplate for matching.
func (c *capableProvider) SupportedAlgorithms() []string { return c.algorithms }

var _ provider.Backend = (*capableProvider)(nil)

// ============================================================================
// MatchForTemplate Tests
// ============================================================================

func TestRegistry_MatchForTemplate_found(t *testing.T) {
	r := provider.NewRegistry()

	p := &capableProvider{
		name:       "software",
		algorithms: []string{"ecdsa-p256-sha256", "ml-dsa-65"},
	}
	_ = r.Register(t.Context(), p)

	got, err := r.MatchForTemplate(t.Context(), "ecdsa-p256-sha256")
	if err != nil {
		t.Fatalf("MatchForTemplate: %v", err)
	}
	if got == nil {
		t.Fatal("MatchForTemplate returned nil provider")
	}
	if got.Name() != "software" {
		t.Errorf("MatchForTemplate: got provider %q want %q", got.Name(), "software")
	}
}

func TestRegistry_MatchForTemplate_notFound(t *testing.T) {
	r := provider.NewRegistry()

	p := &capableProvider{
		name:       "software",
		algorithms: []string{"ecdsa-p256-sha256"},
	}
	_ = r.Register(t.Context(), p)

	_, err := r.MatchForTemplate(t.Context(), "ml-dsa-65") // not in capabilities
	if err == nil {
		t.Fatal("expected error for unmatched template")
	}
}

func TestRegistry_MatchForTemplate_noProviders_returnsError(t *testing.T) {
	r := provider.NewRegistry()
	_, err := r.MatchForTemplate(t.Context(), "ecdsa-p256-sha256")
	if err == nil {
		t.Fatal("expected error when no providers registered")
	}
}

func TestRegistry_MatchForTemplate_multipleProviders_firstMatchReturned(t *testing.T) {
	r := provider.NewRegistry()

	p1 := &capableProvider{
		name:       "loopback",
		algorithms: []string{"ecdsa-p256-sha256"},
	}
	p2 := &capableProvider{
		name:       "software",
		algorithms: []string{"ecdsa-p256-sha256"},
	}
	_ = r.Register(t.Context(), p1)
	_ = r.Register(t.Context(), p2)

	// Both match; loopback was registered first
	got, err := r.MatchForTemplate(t.Context(), "ecdsa-p256-sha256")
	if err != nil {
		t.Fatalf("MatchForTemplate: %v", err)
	}
	if got.Name() != "loopback" {
		t.Errorf("expected first-registered provider, got %q", got.Name())
	}
}

func TestRegistry_MatchForTemplate_providerWithoutSupportedAlgorithms_skipped(t *testing.T) {
	// A provider that doesn't implement SupportedAlgorithms() should be skipped,
	// not cause MatchForTemplate to fail.
	r := provider.NewRegistry()

	// minimalProvider doesn't have SupportedAlgorithms() — should be skipped
	minimal := &minimalProvider{provName: "no-caps"}
	good := &capableProvider{
		name:       "good",
		algorithms: []string{"ecdsa-p256-sha256"},
	}
	_ = r.Register(t.Context(), minimal)
	_ = r.Register(t.Context(), good)

	got, err := r.MatchForTemplate(t.Context(), "ecdsa-p256-sha256")
	if err != nil {
		t.Fatalf("MatchForTemplate: %v", err)
	}
	if got.Name() != "good" {
		t.Errorf("expected to skip provider without SupportedAlgorithms, got %q", got.Name())
	}
}

// minimalProvider is a ProviderInstance without SupportedAlgorithms().
// Used to test that MatchForTemplate gracefully skips such providers.
type minimalProvider struct{ provName string }

func (m *minimalProvider) Name() string { return m.provName }
func (m *minimalProvider) Type() string { return "minimal" }
func (m *minimalProvider) GenerateKey(_ context.Context, _ *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return nil, nil
}
func (m *minimalProvider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return nil, nil
}
func (m *minimalProvider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return nil, nil
}
func (m *minimalProvider) Sign(_ context.Context, _ *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return nil, nil
}
func (m *minimalProvider) Verify(_ context.Context, _ *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return nil, nil
}

var _ provider.Backend = (*minimalProvider)(nil)

// ============================================================================
// MatchForScope Tests
// ============================================================================

func TestRegistry_MatchForScope_M1_returnsDefault(t *testing.T) {
	r := provider.NewRegistry()
	_ = r.Register(t.Context(), &capableProvider{name: "sw", algorithms: []string{"ecdsa-p256-sha256"}})

	got, err := r.MatchForScope(t.Context(), core.ScopeSpec{})
	if err != nil {
		t.Fatalf("MatchForScope: %v", err)
	}
	if got == nil {
		t.Fatal("MatchForScope returned nil")
	}
}
