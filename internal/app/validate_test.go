package app_test

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/template"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/agile-crypto/citius-server/internal/app"
	internaltemplate "github.com/agile-crypto/vault-storage/template"
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
	return &providerpb.GenerateKeyResponse{Output: provider.NoOutput("raw")}, nil
}
func (m *mockProvider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}
func (m *mockProvider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return &providerpb.ExportPublicKeyResponse{Output: provider.NoOutput("raw")}, nil
}
func (m *mockProvider) Sign(_ context.Context, _ *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return &providerpb.SignResponse{Output: provider.NoOutput("raw")}, nil
}
func (m *mockProvider) Verify(_ context.Context, _ *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return &providerpb.VerifyResponse{Output: provider.NoOutputUnencoded()}, nil
}
func (m *mockProvider) SignDigest(_ context.Context, _ *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	return &providerpb.SignDigestResponse{Output: provider.NoOutput("raw")}, nil
}
func (m *mockProvider) VerifyDigest(_ context.Context, _ *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error) {
	return &providerpb.VerifyDigestResponse{Output: provider.NoOutputUnencoded()}, nil
}
func (m *mockProvider) Encrypt(_ context.Context, _ *providerpb.EncryptRequest) (*providerpb.EncryptResponse, error) {
	return &providerpb.EncryptResponse{Output: provider.NoOutput("raw")}, nil
}
func (m *mockProvider) Decrypt(_ context.Context, _ *providerpb.DecryptRequest) (*providerpb.DecryptResponse, error) {
	return &providerpb.DecryptResponse{Output: provider.NoOutputUnencoded()}, nil
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
	return &providerpb.GenerateKeyResponse{Output: provider.NoOutput("raw")}, nil
}
func (b *basicProvider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}
func (b *basicProvider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return &providerpb.ExportPublicKeyResponse{Output: provider.NoOutput("raw")}, nil
}
func (b *basicProvider) Sign(_ context.Context, _ *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return &providerpb.SignResponse{Output: provider.NoOutput("raw")}, nil
}
func (b *basicProvider) Verify(_ context.Context, _ *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return &providerpb.VerifyResponse{Output: provider.NoOutputUnencoded()}, nil
}
func (b *basicProvider) SignDigest(_ context.Context, _ *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	return &providerpb.SignDigestResponse{Output: provider.NoOutput("raw")}, nil
}
func (b *basicProvider) VerifyDigest(_ context.Context, _ *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error) {
	return &providerpb.VerifyDigestResponse{Output: provider.NoOutputUnencoded()}, nil
}
func (b *basicProvider) Encrypt(_ context.Context, _ *providerpb.EncryptRequest) (*providerpb.EncryptResponse, error) {
	return &providerpb.EncryptResponse{Output: provider.NoOutput("raw")}, nil
}
func (b *basicProvider) Decrypt(_ context.Context, _ *providerpb.DecryptRequest) (*providerpb.DecryptResponse, error) {
	return &providerpb.DecryptResponse{Output: provider.NoOutputUnencoded()}, nil
}

var _ provider.Backend = (*basicProvider)(nil)

// signOnlyProvider implements provider.Backend, provider.AlgorithmCapabilityProvider,
// and provider.Signer — but deliberately NOT provider.Cipher (no Encrypt/Decrypt
// methods). Used to prove ValidateProviderCapabilities catches a provider that
// advertises a template whose scoped_capabilities require a capability it
// does not implement.
type signOnlyProvider struct {
	providerName string
	algorithms   []string
}

func (s *signOnlyProvider) Name() string                  { return s.providerName }
func (s *signOnlyProvider) Type() string                  { return "sign-only" }
func (s *signOnlyProvider) SupportedAlgorithms() []string { return s.algorithms }

func (s *signOnlyProvider) GenerateKey(_ context.Context, _ *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	return &providerpb.GenerateKeyResponse{Output: provider.NoOutput("raw")}, nil
}
func (s *signOnlyProvider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}
func (s *signOnlyProvider) ExportPublicKey(_ context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	return &providerpb.ExportPublicKeyResponse{Output: provider.NoOutput("raw")}, nil
}
func (s *signOnlyProvider) Sign(_ context.Context, _ *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	return &providerpb.SignResponse{Output: provider.NoOutput("raw")}, nil
}
func (s *signOnlyProvider) Verify(_ context.Context, _ *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	return &providerpb.VerifyResponse{Output: provider.NoOutputUnencoded()}, nil
}
func (s *signOnlyProvider) SignDigest(_ context.Context, _ *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	return &providerpb.SignDigestResponse{Output: provider.NoOutput("raw")}, nil
}
func (s *signOnlyProvider) VerifyDigest(_ context.Context, _ *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error) {
	return &providerpb.VerifyDigestResponse{Output: provider.NoOutputUnencoded()}, nil
}

// Compile-time checks. signOnlyProvider deliberately has no corresponding
// "_ provider.Cipher = ..." assertion — it does not implement Cipher, which
// is the entire point of this type.
var (
	_ provider.Backend                     = (*signOnlyProvider)(nil)
	_ provider.AlgorithmCapabilityProvider = (*signOnlyProvider)(nil)
	_ provider.Signer                      = (*signOnlyProvider)(nil)
)

// newTestTemplateRegistry creates a VaultRegistry backed by InmemStorage and
// registers the given template IDs as active templates with no
// scoped_capabilities — equivalent to a template declaring no operations, so
// ValidateProviderCapabilities' capability check requires nothing of a
// provider advertising them.
func newTestTemplateRegistry(t *testing.T, templateIDs ...string) template.Registry {
	t.Helper()
	ctx := context.Background()
	reg, err := internaltemplate.NewVaultRegistry(ctx, &logical.InmemStorage{})
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

// newTestTemplateRegistryWithOps is like newTestTemplateRegistry but attaches
// a single ScopedCapabilities entry per template, declaring the given
// operations — the shape ValidateProviderCapabilities' new capability check
// actually reads.
func newTestTemplateRegistryWithOps(t *testing.T, templateID string, ops ...api.CryptoOperation) template.Registry {
	t.Helper()
	ctx := context.Background()
	reg, err := internaltemplate.NewVaultRegistry(ctx, &logical.InmemStorage{})
	if err != nil {
		t.Fatalf("NewVaultRegistry: %v", err)
	}
	err = reg.Register(ctx, template.NewTemplate(&api.TemplateInfo{
		TemplateId: templateID,
		Status:     api.TemplateStatus_TEMPLATE_STATUS_ACTIVE,
		ScopedCapabilities: []*api.ScopedCapabilities{
			{Operations: ops},
		},
	}))
	if err != nil {
		t.Fatalf("Register template %q: %v", templateID, err)
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

func TestValidateProviderCapabilities_missingRequiredCapability_returnsError(t *testing.T) {
	ctx := context.Background()
	// signOnlyProvider implements Signer but not Cipher; advertise it against
	// an AEAD template (needs Cipher) to prove the mismatch is caught.
	tmplReg := newTestTemplateRegistryWithOps(t, "aes-256-gcm-128-96",
		api.CryptoOperation_CRYPTO_OPERATION_ENCRYPT, api.CryptoOperation_CRYPTO_OPERATION_DECRYPT)

	prov := &signOnlyProvider{
		providerName: "sign-only",
		algorithms:   []string{"aes-256-gcm-128-96"},
	}

	err := app.ValidateProviderCapabilities(ctx, prov, tmplReg)
	if err == nil {
		t.Fatal("expected error: provider advertises an encryption template but does not implement Cipher")
	}
	t.Logf("got expected error: %v", err)
}

func TestValidateProviderCapabilities_hasRequiredCapability_succeeds(t *testing.T) {
	ctx := context.Background()
	tmplReg := newTestTemplateRegistryWithOps(t, "ecdsa-p256-sha256",
		api.CryptoOperation_CRYPTO_OPERATION_SIGN, api.CryptoOperation_CRYPTO_OPERATION_VERIFY)

	prov := &signOnlyProvider{
		providerName: "sign-only",
		algorithms:   []string{"ecdsa-p256-sha256"},
	}

	if err := app.ValidateProviderCapabilities(ctx, prov, tmplReg); err != nil {
		t.Errorf("expected no error: provider implements Signer and the template only requires Sign, got: %v", err)
	}
}

func TestValidateProviderCapabilities_templateWithNoScopedCapabilities_succeeds(t *testing.T) {
	ctx := context.Background()
	// newTestTemplateRegistry registers templates with no scoped_capabilities
	// at all — the shape every other test in this file already relies on.
	// The capability check must treat "no operations declared" as "nothing
	// required", not fail closed.
	tmplReg := newTestTemplateRegistry(t, "ecdsa-p256-sha256")

	prov := &signOnlyProvider{
		providerName: "sign-only",
		algorithms:   []string{"ecdsa-p256-sha256"},
	}

	if err := app.ValidateProviderCapabilities(ctx, prov, tmplReg); err != nil {
		t.Errorf("expected no error for a template with no scoped_capabilities, got: %v", err)
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
