package service_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/provider/software"
	"github.ibm.com/citius/citius-server/internal/service"
	"github.ibm.com/citius/citius-server/internal/template"
)

// ============================================================================
// Shared Test Setup
// ============================================================================

// testPolicyName is the name of the permissive policy seeded by setupOrchestrator.
const testPolicyName = "test-allow-all"

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

// setupOrchestrator creates a fully wired KeyOrchestrator backed by in-memory
// storage, the software provider, and the standard algorithm catalog.
//
// The software provider advertises "ecdsa-p256-sha256" and "ml-dsa-65".
// The standard catalog contains "ml-dsa-65" (matching), so end-to-end tests
// use that template ID.
func setupOrchestrator(t *testing.T) service.KeyOrchestrator {
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
	err = template.LoadStandardCatalog(catalogPath(), reg)
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
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if created == nil {
		t.Fatal("CreateKey returned nil key")
	}
	if created.GetPublicId() == "" {
		t.Error("PublicId must not be empty")
	}
	if created.GetName() != "my-mldsa-key" {
		t.Errorf("Name: got %q want %q", created.GetName(), "my-mldsa-key")
	}
	if created.GetCurrentVersion() != 1 {
		t.Errorf("CurrentVersion: got %d want 1", created.GetCurrentVersion())
	}
	if created.GetPrimitive() == "" {
		t.Error("Primitive must not be empty")
	}
}

func TestCreateKey_templateNotFound_returnsError(t *testing.T) {
	orch := setupOrchestrator(t)
	_, err := orch.CreateKey(context.Background(), core.KeyCreationSpec{
		Name:       "key",
		TemplateID: "nonexistent-template",
		PolicyID:   testPolicyName,
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
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// ReadKey is still a stub (CodeNotImplemented), but we verify the key
	// was created successfully with a valid ID.
	if created.GetPublicId() == "" {
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
		Labels:     labels,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	got := created.GetLabels()
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
	_ = template.LoadStandardCatalog(catalogPath(), reg)
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
	if err == nil {
		t.Fatal("expected error when no provider supports the template")
	}
}
