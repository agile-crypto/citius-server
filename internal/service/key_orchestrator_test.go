package service_test

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/service"
	"github.ibm.com/citius/citius-server/internal/template"
)

// ============================================================================
// NewKeyOrchestrator Constructor Tests
// ============================================================================

// allDeps creates a full set of valid dependencies for the constructor.
func allDeps(t *testing.T) (key.Repository, template.Registry, provider.Registry, policy.Engine) {
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
	prov := provider.NewRegistry()
	policyRepo, err := policy.NewVaultRepository(ctx, storage)
	if err != nil {
		t.Fatalf("policy.NewVaultRepository: %v", err)
	}
	eval := policy.NewSimpleRulesEvaluator()
	pol, err := policy.NewEnforcer(policyRepo, eval)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	return repo, reg, prov, pol
}

func TestNewKeyOrchestrator_allDependencies_succeeds(t *testing.T) {
	repo, reg, prov, pol := allDeps(t)
	orch, err := service.NewKeyOrchestrator(repo, reg, prov, pol)
	if err != nil {
		t.Fatalf("NewKeyOrchestrator: %v", err)
	}
	if orch == nil {
		t.Fatal("NewKeyOrchestrator returned nil")
	}
}

func TestNewKeyOrchestrator_nilRepository_returnsError(t *testing.T) {
	_, reg, prov, pol := allDeps(t)
	_, err := service.NewKeyOrchestrator(nil, reg, prov, pol)
	if err == nil {
		t.Fatal("expected error for nil repository")
	}
}

func TestNewKeyOrchestrator_nilTemplateRegistry_returnsError(t *testing.T) {
	repo, _, prov, pol := allDeps(t)
	_, err := service.NewKeyOrchestrator(repo, nil, prov, pol)
	if err == nil {
		t.Fatal("expected error for nil template registry")
	}
}

func TestNewKeyOrchestrator_nilProviderRegistry_returnsError(t *testing.T) {
	repo, reg, _, pol := allDeps(t)
	_, err := service.NewKeyOrchestrator(repo, reg, nil, pol)
	if err == nil {
		t.Fatal("expected error for nil provider registry")
	}
}

func TestNewKeyOrchestrator_nilPolicyEngine_returnsError(t *testing.T) {
	repo, reg, prov, _ := allDeps(t)
	_, err := service.NewKeyOrchestrator(repo, reg, prov, nil)
	if err == nil {
		t.Fatal("expected error for nil policy engine")
	}
}

func TestNewKeyOrchestrator_returnsInterface(t *testing.T) {
	repo, reg, prov, pol := allDeps(t)
	var orch service.KeyOrchestrator
	orch, err := service.NewKeyOrchestrator(repo, reg, prov, pol)
	if err != nil {
		t.Fatalf("NewKeyOrchestrator: %v", err)
	}
	_ = orch // confirms the return type satisfies the interface
}
