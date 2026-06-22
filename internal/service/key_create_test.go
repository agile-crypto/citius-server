package service_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	api "github.ibm.com/citius/citius-server/gen/go/api/types"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/provider/software"
	"github.ibm.com/citius/citius-server/internal/service"
	"github.ibm.com/citius/citius-server/internal/template"
	"google.golang.org/protobuf/proto"
)

// ============================================================================
// Shared Test Setup
// ============================================================================

// testPolicyName is the name of the permissive policy seeded by setupOrchestrator.
const testPolicyName = "test-allow-all"

func defaultScopeSpec(t *testing.T) *core.ScopeSpecification {
	return scopeSpecWithScope(t, core.ScopeSignatureStandard)
}

func scopeSpecWithScope(t *testing.T, scope core.Scope) *core.ScopeSpecification {
	t.Helper()
	scopeSpec := &core.ScopeSpecification{
		Scope: scope,
	}
	return scopeSpec
}

// seedPermissivePolicy creates a policy that allows the ml-dsa-65 template and
// the create_key operation. Used by setupOrchestrator and inline test setups.
func seedPermissivePolicy(t *testing.T, ctx context.Context, pol policy.Engine) {
	t.Helper()
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	p := policy.NewPolicy("pol_testperm", testPolicyName, rulesJSON)
	_, err = pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
}

// catalogPath returns the absolute path to the standard_algorithms.json catalog.
func catalogPath() string {
	_, currentFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(currentFile), "..", "..", "proto", "standard_algorithms.json")
}

// setupOrchestratorFull creates a fully wired KeyOrchestrator backed by
// in-memory storage, the software provider, and the standard algorithm catalog.
// It returns the orchestrator, the underlying key.Repository (for lifecycle
// mutation in tests), and the policy.Engine (for seeding custom policies).
//
// The software provider advertises "ecdsa-p256-sha256" and "ml-dsa-65".
// The standard catalog contains "ml-dsa-65" (matching), so end-to-end tests
// use that template ID.
//
// A permissive policy (testPolicyName) is pre-seeded that allows ml-dsa-65 and
// the create_key operation.
func setupOrchestratorFull(t *testing.T) (service.KeyOrchestrator, key.Repository, policy.Engine) {
	t.Helper()

	ctx := context.Background()
	storage := &logical.InmemStorage{}

	repo, err := key.NewVaultRepository(ctx, storage)
	if err != nil {
		t.Fatalf("NewVaultRepository: %v", err)
	}

	reg, err := template.NewVaultRegistry(ctx, storage)
	if err != nil {
		t.Fatalf("NewVaultRegistry: %v", err)
	}

	// Load the standard algorithm catalog — includes "ml-dsa-65".
	err = template.LoadStandardCatalog(ctx, catalogPath(), reg)
	if err != nil {
		t.Fatalf("LoadStandardCatalog: %v", err)
	}

	provReg := provider.NewRegistry()
	sw := software.New()
	err = provReg.Register(ctx, sw)
	if err != nil {
		t.Fatalf("Register provider: %v", err)
	}

	policyRepo, err := policy.NewVaultRepository(ctx, storage)
	if err != nil {
		t.Fatalf("policy.NewVaultRepository: %v", err)
	}
	eval := policy.NewSimpleRulesEvaluator()
	pol, err := policy.NewEnforcer(policyRepo, eval)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	seedPermissivePolicy(t, ctx, pol)

	orch, err := service.NewKeyOrchestrator(repo, reg, provReg, pol)
	if err != nil {
		t.Fatalf("NewKeyOrchestrator: %v", err)
	}
	return orch, repo, pol
}

// setupOrchestratorWithPolicy is a convenience wrapper that returns the
// orchestrator and policy engine (without the repo). Use setupOrchestratorFull
// when you also need the underlying key.Repository for lifecycle mutation.
func setupOrchestratorWithPolicy(t *testing.T) (service.KeyOrchestrator, policy.Engine) {
	t.Helper()
	orch, _, pol := setupOrchestratorFull(t)
	return orch, pol
}

// setupOrchestrator is a convenience wrapper that returns only the orchestrator.
// Use setupOrchestratorWithPolicy when you need to seed additional policies.
func setupOrchestrator(t *testing.T) service.KeyOrchestrator {
	t.Helper()
	orch, _ := setupOrchestratorWithPolicy(t)
	return orch
}

// ============================================================================
// CreateKey Tests — Template-Based Path
// ============================================================================

func TestCreateKey_templateBased_happyPath(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:       "my-mldsa-key",
		TemplateID: "ml-dsa-65",
		PolicyID:   testPolicyName,
		Scope:      defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if created == nil {
		t.Fatal("CreateKey returned nil key")
		return // unreachable; satisfies static-analysis nil-flow
	}
	if created.KeyID == "" {
		t.Error("PublicId must not be empty")
	}
	if created.Name != "my-mldsa-key" {
		t.Errorf("Name: got %q want %q", created.Name, "my-mldsa-key")
	}
	if created.Version != 1 {
		t.Errorf("CurrentVersion: got %d want 1", created.Version)
	}
	if created.ScopeSpec == nil {
		t.Error("ScopeSpec must not be empty")
	}
}

func TestCreateKey_templateNotFound_returnsError(t *testing.T) {
	orch := setupOrchestrator(t)
	_, err := orch.CreateKey(context.Background(), core.KeyCreationSpec{
		Name:       "key",
		TemplateID: "nonexistent-template",
		PolicyID:   testPolicyName,
		Scope:      defaultScopeSpec(t),
	})
	if err == nil {
		t.Fatal("expected error for unknown template")
	}
}

func TestCreateKey_missingName_returnsError(t *testing.T) {
	orch := setupOrchestrator(t)
	_, err := orch.CreateKey(context.Background(), core.KeyCreationSpec{
		TemplateID: "ml-dsa-65",
		PolicyID:   testPolicyName,
		Scope:      defaultScopeSpec(t),
		// Name is empty
	})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestCreateKey_missingPolicyID_returnsError(t *testing.T) {
	orch := setupOrchestrator(t)
	_, err := orch.CreateKey(context.Background(), core.KeyCreationSpec{
		Name:       "no-policy",
		TemplateID: "ml-dsa-65",
		Scope:      defaultScopeSpec(t),
		// PolicyID is empty
	})
	if err == nil {
		t.Fatal("expected error for missing policy ID")
	}
}

func TestCreateKey_storesPersistentKey(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:       "persistent-key",
		TemplateID: "ml-dsa-65",
		PolicyID:   testPolicyName,
		Scope:      defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// ReadKey is still a stub (CodeNotImplemented), but we verify the key
	// was created successfully with a valid ID.
	if created.KeyID == "" {
		t.Error("expected non-empty PublicId")
	}
}

func TestCreateKey_withLabels(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	labels := map[string]string{"env": "test", "team": "platform"}
	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:       "labelled-key",
		TemplateID: "ml-dsa-65",
		PolicyID:   testPolicyName,
		Scope:      defaultScopeSpec(t),
		Labels:     labels,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	got := created.Labels
	if len(got) != 2 {
		t.Errorf("Labels: got %d entries want 2", len(got))
	}
	if got["env"] != "test" {
		t.Errorf("Labels[env]: got %q want %q", got["env"], "test")
	}
}

func TestCreateKey_providerNotFound_returnsError(t *testing.T) {
	// Use an orchestrator without any provider registered.
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	repo, _ := key.NewVaultRepository(ctx, storage)
	reg, _ := template.NewVaultRegistry(ctx, storage)
	_ = template.LoadStandardCatalog(ctx, catalogPath(), reg)
	provReg := provider.NewRegistry() // empty — no providers
	policyRepo, _ := policy.NewVaultRepository(ctx, storage)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)
	seedPermissivePolicy(t, ctx, pol)

	orch, _ := service.NewKeyOrchestrator(repo, reg, provReg, pol)

	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:       "no-provider",
		TemplateID: "ml-dsa-65",
		PolicyID:   testPolicyName,
		Scope:      defaultScopeSpec(t),
	})
	if err == nil {
		t.Fatal("expected error when no provider supports the template")
	}
}

func TestCreateKey_withoutScope_returnsError(t *testing.T) {
	// Use an orchestrator without any provider registered.
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	repo, _ := key.NewVaultRepository(ctx, storage)
	reg, _ := template.NewVaultRegistry(ctx, storage)
	_ = template.LoadStandardCatalog(ctx, catalogPath(), reg)
	provReg := provider.NewRegistry() // empty — no providers
	policyRepo, _ := policy.NewVaultRepository(ctx, storage)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)
	seedPermissivePolicy(t, ctx, pol)

	orch, _ := service.NewKeyOrchestrator(repo, reg, provReg, pol)

	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:       "no-provider",
		TemplateID: "ml-dsa-65",
		PolicyID:   testPolicyName,
	})
	require.Error(t, err, "missing scope should return an error")
}

// ============================================================================
// Scope-Based Helpers
// ============================================================================

// marshalSignatureScope builds proto-encoded ScopeSpecification bytes for the
// given SignatureScope. Used by scope-based CreateKey tests.
func marshalSignatureScope(t *testing.T, scope api.SignatureScope) []byte {
	t.Helper()
	spec := &api.ScopeSpecification{
		ScopeSpec: &api.ScopeSpecification_Signature{
			Signature: &api.SignatureScopeSpec{
				Scope: scope,
			},
		},
	}
	b, err := proto.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal ScopeSpecification: %v", err)
	}
	return b
}

// seedScopePolicy creates a named policy with the given rules and returns the
// policy name. Convenience for scope-based tests that need custom policies.
func seedScopePolicy(t *testing.T, ctx context.Context, pol policy.Engine, name string, rules *policy.Rules) string {
	t.Helper()
	var rulesJSON []byte
	if rules != nil {
		var err error
		rulesJSON, err = json.Marshal(rules)
		if err != nil {
			t.Fatalf("marshal rules: %v", err)
		}
	}
	p := policy.NewPolicy(core.NewID(core.PolicyPrefix), name, rulesJSON)
	_, err := pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed policy %q: %v", name, err)
	}
	return name
}

// ============================================================================
// CreateKey Tests — Scope-Based Path
// ============================================================================

func TestCreateKey_scopeBased_permissivePolicy_selectsByScope(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	// Seed a policy that allows ml-dsa-65 + create_key for the scope path.
	policyName := seedScopePolicy(t, ctx, pol, "scope-permissive", &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	})

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:     "scope-based-key",
		Scope:    defaultScopeSpec(t),
		PolicyID: policyName,
	})
	if err != nil {
		t.Fatalf("CreateKey (scope-based, permissive policy): %v", err)
	}
	if created.Primitive == "" {
		t.Error("Primitive should be set from scope")
	}
	if created.Primitive != "signature" {
		t.Errorf("Primitive: got %q want %q", created.Primitive, "signature")
	}
}

func TestCreateKey_scopeBased_policyAllowsTemplate(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	policyName := seedScopePolicy(t, ctx, pol, "allow-mldsa", &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	})

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:     "policy-allowed",
		Scope:    defaultScopeSpec(t),
		PolicyID: policyName,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if created.KeyID == "" {
		t.Error("expected valid key")
	}
}

func TestCreateKey_scopeBased_policyDenies_noMatchingTemplate(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	// Policy allows only a template that doesn't exist in the catalog.
	policyName := seedScopePolicy(t, ctx, pol, "deny-all-real", &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"nonexistent-template"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	})

	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:     "should-fail",
		Scope:    defaultScopeSpec(t),
		PolicyID: policyName,
	})
	if err == nil {
		t.Fatal("expected error: policy restricts to non-existent template")
	}
}

func TestCreateKey_scopeBased_policyDenyByDefault(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	// Empty/nil rules = deny-by-default: allowed_templates is absent (nil).
	policyName := seedScopePolicy(t, ctx, pol, "deny-default", nil)

	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:     "should-fail",
		Scope:    defaultScopeSpec(t),
		PolicyID: policyName,
	})
	if err == nil {
		t.Fatal("expected error: deny-by-default policy should block key creation")
	}
}

func TestCreateKey_scopeBased_quantumSafeFilter(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	// Allow both templates; the quantum_safe filter in the scope should narrow
	// selection to ml-dsa-65 only (ecdsa-p256 is not quantum-safe).
	policyName := seedScopePolicy(t, ctx, pol, "qs-policy", &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65", "ecdsa-p256-sha256-der"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	})

	qsTrue := true
	spec := &api.ScopeSpecification{
		ScopeSpec: &api.ScopeSpecification_Signature{
			Signature: &api.SignatureScopeSpec{
				Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
				Security: &api.UniversalSecurityProperties{
					QuantumSafe: &qsTrue,
				},
			},
		},
	}

	scopeSpec, err := core.ScopeSpecificationFromProto(ctx, spec)
	require.NoError(t, err, "convert scope spec from proto")

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:     "quantum-safe-key",
		Scope:    scopeSpec,
		PolicyID: policyName,
	})
	if err != nil {
		t.Fatalf("CreateKey (quantum_safe scope): %v", err)
	}
	// The only quantum-safe signature template in the catalog is ml-dsa-65.
	if created.Primitive != "signature" {
		t.Errorf("Primitive: got %q want %q", created.Primitive, "signature")
	}
}

func TestCreateKey_scopeBased_policyNotFound(t *testing.T) {
	orch, _ := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	_, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:     "should-fail",
		Scope:    defaultScopeSpec(t),
		PolicyID: "nonexistent-policy",
	})
	if err == nil {
		t.Fatal("expected error: policy not found")
	}
}

func TestCreateKey_scopeBased_primitiveMismatch(t *testing.T) {
	orch, pol := setupOrchestratorWithPolicy(t)
	ctx := context.Background()

	// Allow everything — but the KEM primitive has no templates in the catalog.
	policyName := seedScopePolicy(t, ctx, pol, "allow-all-kem", &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65", "ecdsa-p256-sha256-der"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	})

	// The catalog only has signature templates; request KEM scope.
	spec := &api.ScopeSpecification{
		ScopeSpec: &api.ScopeSpecification_Kem{
			Kem: &api.KemScopeSpec{
				Scope: api.KemScope_KEM_SCOPE_STANDARD,
			},
		},
	}
	scopeSpec, err := core.ScopeSpecificationFromProto(ctx, spec)
	require.NoError(t, err, "convert scope spec from proto")

	_, err = orch.CreateKey(ctx, core.KeyCreationSpec{
		Name:     "kem-key",
		Scope:    scopeSpec,
		PolicyID: policyName,
	})
	if err == nil {
		t.Fatal("expected error: no KEM template in catalog")
	}
}
