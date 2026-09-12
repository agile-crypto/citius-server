package service_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/agile-crypto/citius-core/service"

	core "github.com/agile-crypto/citius-core"
	corekey "github.com/agile-crypto/citius-core/key"
	corepolicy "github.com/agile-crypto/citius-core/policy"
	coreprovider "github.com/agile-crypto/citius-core/provider"
	coretemplate "github.com/agile-crypto/citius-core/template"
	"github.com/agile-crypto/citius-server/internal/provider/software"
	"github.com/agile-crypto/vault-storage/key"
	"github.com/agile-crypto/vault-storage/policy"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/agile-crypto/vault-storage/template"
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
func seedPermissivePolicy(t *testing.T, ctx context.Context, pol corepolicy.Engine) {
	t.Helper()
	rules := &corepolicy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &corepolicy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	p := corepolicy.NewPolicy("pol_testperm", testPolicyName, rulesJSON)
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

// setupOrchestratorFull creates a fully wired service.KeyOrchestrator backed by
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
func setupOrchestratorFull(t *testing.T) (service.KeyOrchestrator, corekey.Repository, coreprovider.Registry, corepolicy.Engine, coretemplate.Registry) {
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
	err = coretemplate.LoadStandardCatalog(ctx, catalogPath(), reg)
	if err != nil {
		t.Fatalf("LoadStandardCatalog: %v", err)
	}

	provReg := coreprovider.NewRegistry()
	sw := software.New()
	err = provReg.Register(ctx, sw)
	if err != nil {
		t.Fatalf("Register provider: %v", err)
	}

	policyRepo, err := policy.NewVaultRepository(ctx, storage)
	if err != nil {
		t.Fatalf("policy.NewVaultRepository: %v", err)
	}
	eval := corepolicy.NewSimpleRulesEvaluator()
	pol, err := corepolicy.NewEnforcer(policyRepo, eval)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	seedPermissivePolicy(t, ctx, pol)

	orch, err := service.NewKeyOrchestrator(repo, reg, provReg, pol)
	if err != nil {
		t.Fatalf("service.NewKeyOrchestrator: %v", err)
	}
	return orch, repo, provReg, pol, reg
}

// setupOrchestratorWithPolicy is a convenience wrapper that returns the
// orchestrator and policy engine (without the repo). Use setupOrchestratorFull
// when you also need the underlying key.Repository for lifecycle mutation.
func setupOrchestratorWithPolicy(t *testing.T) (service.KeyOrchestrator, corepolicy.Engine) {
	t.Helper()
	orch, _, _, pol, _ := setupOrchestratorFull(t)
	return orch, pol
}

// setupOrchestrator is a convenience wrapper that returns only the orchestrator.
// Use setupOrchestratorWithPolicy when you need to seed additional policies.
func setupOrchestrator(t *testing.T) service.KeyOrchestrator {
	t.Helper()
	orch, _ := setupOrchestratorWithPolicy(t)
	return orch
}
