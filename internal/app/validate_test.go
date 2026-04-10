package app_test

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
	api "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/app"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/template"
)

// ============================================================================
// Test doubles
// ============================================================================

// mockProvider implements both provider.Backend and
// provider.AlgorithmCapabilityProvider with configurable SupportedAlgorithms.
type mockProvider struct {
	providerName string
	algorithms   []string
}

func (m *mockProvider) Name() string                  { return m.providerName }
func (m *mockProvider) Type() string                  { return "mock" }
func (m *mockProvider) SupportedAlgorithms() []string { return m.algorithms }

func (m *mockProvider) GenerateKey(_ context.Context, _ *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return &providerpb.GenerateKeyResponse{}, nil
}
func (m *mockProvider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}
func (m *mockProvider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return &providerpb.ExportPublicKeyResponse{}, nil
}
func (m *mockProvider) Sign(_ context.Context, _ *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return &providerpb.SignResponse{}, nil
}
func (m *mockProvider) Verify(_ context.Context, _ *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return &providerpb.VerifyResponse{}, nil
}

// Compile-time checks.
var (
	_ provider.Backend                     = (*mockProvider)(nil)
	_ provider.AlgorithmCapabilityProvider = (*mockProvider)(nil)
)

// basicProvider implements only provider.Backend — it does NOT implement
// AlgorithmCapabilityProvider, so validation should be skipped.
type basicProvider struct {
	providerName string
}

func (b *basicProvider) Name() string { return b.providerName }
func (b *basicProvider) Type() string { return "basic" }

func (b *basicProvider) GenerateKey(_ context.Context, _ *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return &providerpb.GenerateKeyResponse{}, nil
}
func (b *basicProvider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}
func (b *basicProvider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return &providerpb.ExportPublicKeyResponse{}, nil
}
func (b *basicProvider) Sign(_ context.Context, _ *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return &providerpb.SignResponse{}, nil
}
func (b *basicProvider) Verify(_ context.Context, _ *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return &providerpb.VerifyResponse{}, nil
}

var _ provider.Backend = (*basicProvider)(nil)

// newTestTemplateRegistry creates a VaultRegistry backed by InmemStorage and
// registers the given template IDs as active templates.
func newTestTemplateRegistry(t *testing.T, templateIDs ...string) template.Registry {
	t.Helper()
	ctx := context.Background()
	reg, err := template.NewVaultRegistry(ctx, &logical.InmemStorage{})
	if err != nil {
		t.Fatalf("NewVaultRegistry: %v", err)
	}
	for _, id := range templateIDs {
		err = reg.Register(ctx, template.NewTemplate(&api.TemplateInfo{
			TemplateId: id,
			Status:     api.TemplateStatus_TEMPLATE_STATUS_ACTIVE,
		}))
		if err != nil {
			t.Fatalf("Register template %q: %v", id, err)
		}
	}
	return reg
}

// ============================================================================
// ValidateProviderCapabilities
// ============================================================================

func TestValidateProviderCapabilities_allAlgorithmsExist_succeeds(t *testing.T) {
	ctx := context.Background()
	tmplReg := newTestTemplateRegistry(t, "ecdsa-p256-sha256", "ml-dsa-65")

	prov := &mockProvider{
		providerName: "test-provider",
		algorithms:   []string{"ecdsa-p256-sha256", "ml-dsa-65"},
	}

	if err := app.ValidateProviderCapabilities(ctx, prov, tmplReg); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateProviderCapabilities_unknownAlgorithm_returnsError(t *testing.T) {
	ctx := context.Background()
	tmplReg := newTestTemplateRegistry(t, "ecdsa-p256-sha256")

	prov := &mockProvider{
		providerName: "test-provider",
		algorithms:   []string{"ecdsa-p256-sha256", "nonexistent-algorithm"},
	}

	err := app.ValidateProviderCapabilities(ctx, prov, tmplReg)
	if err == nil {
		t.Fatal("expected error for unknown algorithm, got nil")
	}
	t.Logf("got expected error: %v", err)
}

func TestValidateProviderCapabilities_providerWithoutCapabilities_succeeds(t *testing.T) {
	ctx := context.Background()
	tmplReg := newTestTemplateRegistry(t)

	prov := &basicProvider{providerName: "basic"}

	if err := app.ValidateProviderCapabilities(ctx, prov, tmplReg); err != nil {
		t.Errorf("expected no error for provider without capabilities, got: %v", err)
	}
}

func TestValidateProviderCapabilities_emptyAlgorithmList_succeeds(t *testing.T) {
	ctx := context.Background()
	tmplReg := newTestTemplateRegistry(t)

	prov := &mockProvider{
		providerName: "empty-provider",
		algorithms:   []string{},
	}

	if err := app.ValidateProviderCapabilities(ctx, prov, tmplReg); err != nil {
		t.Errorf("expected no error for empty algorithm list, got: %v", err)
	}
}

// ============================================================================
// ValidateAllProviders
// ============================================================================

func TestValidateAllProviders_oneInvalid_returnsError(t *testing.T) {
	ctx := context.Background()
	tmplReg := newTestTemplateRegistry(t, "ecdsa-p256-sha256")

	provReg := provider.NewRegistry()
	_ = provReg.Register(ctx, &mockProvider{
		providerName: "good-provider",
		algorithms:   []string{"ecdsa-p256-sha256"},
	})
	_ = provReg.Register(ctx, &mockProvider{
		providerName: "bad-provider",
		algorithms:   []string{"unknown-algorithm"},
	})

	err := app.ValidateAllProviders(ctx, provReg, tmplReg)
	if err == nil {
		t.Fatal("expected error for bad provider, got nil")
	}
	t.Logf("got expected error: %v", err)
}

func TestValidateAllProviders_allValid_succeeds(t *testing.T) {
	ctx := context.Background()
	tmplReg := newTestTemplateRegistry(t, "ecdsa-p256-sha256", "ml-dsa-65")

	provReg := provider.NewRegistry()
	_ = provReg.Register(ctx, &mockProvider{
		providerName: "provider-a",
		algorithms:   []string{"ecdsa-p256-sha256"},
	})
	_ = provReg.Register(ctx, &mockProvider{
		providerName: "provider-b",
		algorithms:   []string{"ml-dsa-65"},
	})

	if err := app.ValidateAllProviders(ctx, provReg, tmplReg); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}
