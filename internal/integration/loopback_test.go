// Package integration contains end-to-end tests for the CaaS core.
// These tests wire the entire system via requestWiring → ForStorage, over the
// same internal/storage repositories and storage.InmemStorage as the gRPC
// server (the *_vault_test.go files run the same tests through vault.Service
// and Vault's logical.Storage, under the vault_plugin build tag), and
// verify that all components (orchestrators, policy, template registry,
// provider registry) work together through the factory wiring.
//
// The loopback provider is used for deterministic verification:
//   - GenerateKey returns synthetic fixed bytes ("LOOPBACK_PUB", "LOOPBACK_PRIV")
//   - Sign echoes the input as the signature
//   - Verify returns true iff signature == input
//
// This makes tests 100% hermetic — no real crypto, no external dependencies.
package integration

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	api "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/service"
	"github.com/agile-crypto/citius-core/storage"
	"github.com/agile-crypto/citius-core/template"
	"github.com/agile-crypto/citius-server/internal/app"
	"github.com/agile-crypto/citius-server/internal/provider/loopback"
)

// ============================================================================
// Wiring Helpers
// ============================================================================

// catalogPath returns the absolute path to standard_algorithms.json.
func catalogPath() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "proto", "standard_algorithms.json")
}

// wireLoopback builds a fully wired requestWiring backed by the loopback provider.
// Templates are loaded from the standard catalog; the loopback provider handles
// both ecdsa-p256-sha256-der and ml-dsa-65.
func wireLoopback(t *testing.T) *requestWiring {
	t.Helper()
	ctx := context.Background()

	// Shared template registry — loaded once, used across all ForStorage calls.
	bootstrapStorage := &storage.InmemStorage{}
	reg, err := template.NewVaultRegistry(ctx, bootstrapStorage)
	if err != nil {
		t.Fatalf("NewVaultRegistry: %v", err)
	}
	err = template.LoadStandardCatalog(context.Background(), catalogPath(), reg)
	if err != nil {
		t.Fatalf("LoadStandardCatalog: %v", err)
	}

	// Shared provider registry — loopback only.
	provReg := provider.NewRegistry()
	err = provReg.Register(ctx, loopback.New())
	if err != nil {
		t.Fatalf("Register loopback: %v", err)
	}

	// Validate provider capabilities against templates (fail-fast).
	err = app.ValidateAllProviders(ctx, provReg, reg)
	if err != nil {
		t.Fatalf("ValidateAllProviders: %v", err)
	}

	return &requestWiring{templates: reg, providers: provReg}
}

// requestWiring is the non-Vault counterpart of vault.Service. It builds the
// orchestrators and policy engine the way the gRPC server does
// (internal/cmd/server wireFactoriesWithStorage): the internal/storage
// repositories over a storage.Storage, with shared template and provider
// registries. The provider registry is injected so the tests can use the
// loopback or software provider alone.
type requestWiring struct {
	templates template.Registry
	providers provider.Registry
}

// requestScope holds one storage's orchestrators and policy engine.
type requestScope struct {
	keys      service.KeyOrchestrator
	cryptoOps service.CryptoOrchestrator
	policy    policy.Engine
}

func (r *requestScope) Keys() service.KeyOrchestrator      { return r.keys }
func (r *requestScope) Crypto() service.CryptoOrchestrator { return r.cryptoOps }
func (r *requestScope) Policy() policy.Engine              { return r.policy }

// ForStorage builds a requestScope whose repositories all share store.
func (w *requestWiring) ForStorage(ctx context.Context, store storage.Storage) (*requestScope, error) {
	keys, err := buildKeyOrchestrator(ctx, store, w.templates, w.providers)
	if err != nil {
		return nil, err
	}
	cryptoOps, err := buildCryptoOrchestrator(ctx, store, w.templates, w.providers)
	if err != nil {
		return nil, err
	}
	pol, err := buildPolicyEngine(ctx, store)
	if err != nil {
		return nil, err
	}
	return &requestScope{keys: keys, cryptoOps: cryptoOps, policy: pol}, nil
}

// seedPolicy creates a policy in the request scope that allows the given
// templates and operations, then returns the policy name.
func seedPolicy(t *testing.T, ctx context.Context, pol policy.Engine,
	name string, templates []string, ops []core.Operation) string {
	t.Helper()
	keyOps := make([]string, len(ops))
	for i, op := range ops {
		keyOps[i] = string(op)
	}
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: templates,
		AllowedOperations: &policy.OperationRule{
			KeyOperations: keyOps,
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	p := policy.NewPolicy(core.NewID(core.PolicyPrefix), name, rulesJSON)
	if _, err := pol.CreatePolicy(ctx, p); err != nil {
		t.Fatalf("seed policy %q: %v", name, err)
	}
	return name
}

// sigScopeSpec returns a minimal ScopeSpecification carrying the standard
// signature scope, satisfying CreateKey's requirement that the scope
// specification must not be nil and contain at least a scope.
func sigScopeSpec() *core.ScopeSpecification {
	return &core.ScopeSpecification{Scope: core.ScopeSignatureStandard}
}

// ============================================================================
// Factory Builders - avoids govet shadow inside closures
// ============================================================================

func buildKeyOrchestrator(
	ctx context.Context, s storage.Storage,
	reg template.Registry, provReg provider.Registry,
) (service.KeyOrchestrator, error) {
	repo, err := key.NewStorageRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	policyRepo, err := policy.NewStorageRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	pol, err := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
	if err != nil {
		return nil, err
	}
	return service.NewKeyOrchestrator(repo, reg, provReg, pol)
}

func buildCryptoOrchestrator(
	ctx context.Context, s storage.Storage,
	reg template.Registry, provReg provider.Registry,
) (service.CryptoOrchestrator, error) {
	repo, err := key.NewStorageRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	policyRepo, err := policy.NewStorageRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	pol, err := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
	if err != nil {
		return nil, err
	}
	return service.NewCryptoOrchestrator(repo, pol, provReg, reg)
}

func buildPolicyEngine(
	ctx context.Context, s storage.Storage,
) (policy.Engine, error) {
	policyRepo, err := policy.NewStorageRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	return policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
}

// ============================================================================
// Integration Tests — Loopback Provider
// ============================================================================

func TestIntegration_Loopback_CreateKey_Sign_Verify_ECDSA(t *testing.T) {
	svc := wireLoopback(t)
	ctx := context.Background()
	store := &storage.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"ecdsa-allow",
		[]string{"ecdsa-p256-sha256-der"},
		[]core.Operation{core.OperationCreateKey, core.OperationSign, core.OperationVerify},
	)

	// Create key
	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "loopback-ecdsa-key",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           policyName,
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if createdKey.KeyID == "" {
		t.Fatal("created key has empty PublicID")
	}
	t.Logf("Created key: %s (primitive: %s)", createdKey.KeyID, createdKey.Primitive)

	keyName := createdKey.Name

	// Sign
	payload := []byte("integration test payload — ECDSA with loopback")
	signResult, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signResult.Signature) == 0 {
		t.Fatal("expected non-empty signature")
	}
	t.Logf("Signed: algorithm=%s provider=%s", signResult.Algorithm, signResult.ProviderName)

	// Verify
	verifyResult, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Payload:              payload,
		Signature:            signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("integration: Sign+Verify round-trip FAILED (loopback ECDSA)")
	}
	t.Log("ECDSA loopback round-trip: PASSED")
}

func TestIntegration_Loopback_CreateKey_Sign_Verify_MLDSA(t *testing.T) {
	svc := wireLoopback(t)
	ctx := context.Background()
	store := &storage.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"mldsa-allow",
		[]string{"ml-dsa-65"},
		[]core.Operation{core.OperationCreateKey, core.OperationSign, core.OperationVerify},
	)

	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "loopback-mldsa-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           policyName,
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey ml-dsa-65: %v", err)
	}

	keyName := createdKey.Name
	payload := []byte("post-quantum integration test with loopback")

	signResult, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign ml-dsa-65: %v", err)
	}

	verifyResult, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Payload:              payload,
		Signature:            signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify ml-dsa-65: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("integration: Sign+Verify round-trip FAILED (loopback ML-DSA-65)")
	}
	t.Log("ML-DSA-65 loopback round-trip: PASSED")
}

func TestIntegration_Loopback_TamperedPayload_ReturnsFalse(t *testing.T) {
	svc := wireLoopback(t)
	ctx := context.Background()
	store := &storage.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"tamper-allow",
		[]string{"ecdsa-p256-sha256-der"},
		[]core.Operation{core.OperationCreateKey, core.OperationSign, core.OperationVerify},
	)

	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "tamper-test-key",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           policyName,
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	keyName := createdKey.Name

	signResult, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              []byte("original"),
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify with tampered payload — should return valid=false, NOT an error.
	verifyResult, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Payload:              []byte("tampered"),
		Signature:            signResult.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify with tampered payload should not error: %v", err)
	}
	if verifyResult.Valid {
		t.Error("tampered payload should return valid=false")
	}
	t.Log("Tampered payload returns valid=false: PASSED")
}

func TestIntegration_Loopback_ScopeBased_CreateKey(t *testing.T) {
	svc := wireLoopback(t)
	ctx := context.Background()
	store := &storage.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	// Policy allows ml-dsa-65 via scope-based selection.
	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"scope-allow",
		[]string{"ml-dsa-65"},
		[]core.Operation{core.OperationCreateKey},
	)

	// Build proto-encoded ScopeSpecification for SIGNATURE_SCOPE_STANDARD.
	spec := &api.ScopeSpecification{
		ScopeSpec: &api.ScopeSpecification_Signature{
			Signature: &api.SignatureScopeSpec{
				Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
			},
		},
	}
	scopeSpec, err := core.ScopeSpecificationFromProto(ctx, spec)
	if err != nil {
		t.Fatalf("convert ScopeSpecification: %v", err)
	}

	// Create key by scope — the registry selects the best matching template.
	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "scope-based-key",
		ScopeSpecification: scopeSpec,
		PolicyID:           policyName,
	})
	if err != nil {
		t.Fatalf("scope-based CreateKey: %v", err)
	}
	if createdKey.Primitive != "signature" {
		t.Errorf("expected primitive %q, got %q", "signature", createdKey.Primitive)
	}
	t.Logf("Scope-based CreateKey resolved key: %s (primitive: %s)",
		createdKey.KeyID, createdKey.Primitive)
}

func TestIntegration_Loopback_MultipleKeys_IsolatedStorage(t *testing.T) {
	svc := wireLoopback(t)
	ctx := context.Background()

	// Each ForStorage call gets its own InmemStorage — keys are isolated.
	store1 := &storage.InmemStorage{}
	store2 := &storage.InmemStorage{}

	requestScope1, err := svc.ForStorage(ctx, store1)
	if err != nil {
		t.Fatalf("ForStorage(store1): %v", err)
	}
	requestScope2, err := svc.ForStorage(ctx, store2)
	if err != nil {
		t.Fatalf("ForStorage(store2): %v", err)
	}

	// Seed identical policies in both stores.
	pol1Name := seedPolicy(t, ctx, requestScope1.Policy(),
		"iso-allow",
		[]string{"ecdsa-p256-sha256-der"},
		[]core.Operation{core.OperationCreateKey, core.OperationReadKey},
	)
	seedPolicy(t, ctx, requestScope2.Policy(),
		"iso-allow",
		[]string{"ecdsa-p256-sha256-der"},
		[]core.Operation{core.OperationCreateKey, core.OperationReadKey},
	)

	k1, err := requestScope1.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name: "key-in-store1", TemplateID: "ecdsa-p256-sha256-der", PolicyID: pol1Name, ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey in store1: %v", err)
	}
	k2, err := requestScope2.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name: "key-in-store2", TemplateID: "ecdsa-p256-sha256-der", PolicyID: pol1Name, ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey in store2: %v", err)
	}

	if k1.KeyID == k2.KeyID {
		t.Error("keys in different stores should have different IDs")
	}

	// Key from requestScope1 should not be found in requestScope2.
	_, readErr := requestScope2.Keys().ReadKey(ctx, k1.Name, 0)
	if readErr == nil {
		t.Error("key from requestScope1 should not be visible in requestScope2 (storage isolation)")
	}
	t.Log("Storage isolation between requestScope instances: PASSED")
}

func TestIntegration_Loopback_TransformKey_Sign_Verify(t *testing.T) {
	svc := wireLoopback(t)
	ctx := context.Background()
	store := &storage.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	// Policy must allow both the original and the target template for
	// CreateKey — TransformKey re-validates via core.OperationCreateKey.
	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"transform-allow",
		[]string{"ecdsa-p256-sha256-der", "ml-dsa-65"},
		[]core.Operation{core.OperationCreateKey, core.OperationSign, core.OperationVerify},
	)

	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "loopback-transform-key",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           policyName,
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyName := createdKey.Name

	// Sanity check: v1 (ECDSA) signs and verifies before transforming.
	payload := []byte("integration test payload — transform with loopback")
	signV1, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign (v1): %v", err)
	}
	if signV1.KeyVersion != 1 {
		t.Fatalf("expected v1 to sign with version 1, got %d", signV1.KeyVersion)
	}

	// Transform the key to ml-dsa-65 — should produce version 2.
	transformedMeta, err := requestScope.Keys().TransformKey(ctx, service.TransformKeySpec{
		KeyName:            keyName,
		TemplateID:         "ml-dsa-65",
		ScopeSpecification: sigScopeSpec(),
	})
	if err != nil {
		t.Fatalf("TransformKey: %v", err)
	}
	if transformedMeta.TemplateID != "ml-dsa-65" {
		t.Errorf("TransformKey: expected template ml-dsa-65, got %s", transformedMeta.TemplateID)
	}
	if transformedMeta.Version != 2 {
		t.Errorf("TransformKey: expected version 2, got %d", transformedMeta.Version)
	}
	t.Logf("Transformed key: %s -> template=%s version=%d", keyName, transformedMeta.TemplateID, transformedMeta.Version)

	// Sign+Verify round-trip on the transformed (current) version.
	signV2, err := requestScope.Crypto().Sign(ctx, crypto.SignRequest{
		KeyName:              keyName,
		Payload:              payload,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign (v2, post-transform): %v", err)
	}
	if signV2.KeyVersion != 2 {
		t.Fatalf("expected post-transform sign to use version 2, got %d", signV2.KeyVersion)
	}

	verifyV2, err := requestScope.Crypto().Verify(ctx, crypto.VerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signV2.KeyVersion,
		Payload:              payload,
		Signature:            signV2.Signature,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &api.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify (v2, post-transform): %v", err)
	}
	if !verifyV2.Valid {
		t.Error("TransformKey round-trip FAILED: Sign+Verify on transformed version is not valid")
	}
	t.Log("TransformKey Sign+Verify round-trip (loopback): PASSED")
}
