package service

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/provider/software"
	"github.ibm.com/citius/citius-server/internal/template"
)

// ============================================================================
// Shared Crypto Orchestrator Setup
// ============================================================================

// setupCryptoOrchestratorFull creates a fully wired CryptoOrchestrator backed
// by in-memory storage, the software provider, and the standard algorithm
// catalog. It returns the CryptoOrchestrator, KeyOrchestrator (for creating
// keys in tests), and policy.Engine (for seeding custom policies).
func setupCryptoOrchestratorFull(t *testing.T) (CryptoOrchestrator, KeyOrchestrator, policy.Engine) {
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

	keyOrch, err := NewKeyOrchestrator(repo, reg, provReg, pol)
	if err != nil {
		t.Fatalf("NewKeyOrchestrator: %v", err)
	}

	ops, err := NewCryptoOrchestrator(storage, repo, pol, provReg, reg)
	if err != nil {
		t.Fatalf("NewCryptoOrchestrator: %v", err)
	}
	return ops, keyOrch, pol
}

// setupCryptoOrchestrator is a convenience wrapper that returns only the
// CryptoOrchestrator. Use setupCryptoOrchestratorFull when you also need
// the KeyOrchestrator or policy.Engine.
func setupCryptoOrchestrator(t *testing.T) CryptoOrchestrator {
	t.Helper()
	ops, _, _ := setupCryptoOrchestratorFull(t)
	return ops
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNewCryptoOrchestrator_allDependencies_succeeds(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	if ops == nil {
		t.Fatal("NewCryptoOrchestrator returned nil")
	}
}

func TestNewCryptoOrchestrator_nilStorage_returnsError(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	repo, _ := key.NewVaultRepository(ctx, storage)
	reg, _ := template.NewVaultRegistry(ctx, storage)
	provReg := provider.NewRegistry()
	policyRepo, _ := policy.NewVaultRepository(ctx, storage)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)

	_, err := NewCryptoOrchestrator(nil, repo, pol, provReg, reg)
	if err == nil {
		t.Fatal("expected error for nil storage")
	}
}

func TestNewCryptoOrchestrator_nilKeyReader_returnsError(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	reg, _ := template.NewVaultRegistry(ctx, storage)
	provReg := provider.NewRegistry()
	policyRepo, _ := policy.NewVaultRepository(ctx, storage)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)

	_, err := NewCryptoOrchestrator(storage, nil, pol, provReg, reg)
	if err == nil {
		t.Fatal("expected error for nil key reader")
	}
}

func TestNewCryptoOrchestrator_nilPolicyEngine_returnsError(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	repo, _ := key.NewVaultRepository(ctx, storage)
	reg, _ := template.NewVaultRegistry(ctx, storage)
	provReg := provider.NewRegistry()

	_, err := NewCryptoOrchestrator(storage, repo, nil, provReg, reg)
	if err == nil {
		t.Fatal("expected error for nil policy engine")
	}
}

func TestNewCryptoOrchestrator_nilProviderRegistry_returnsError(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	repo, _ := key.NewVaultRepository(ctx, storage)
	reg, _ := template.NewVaultRegistry(ctx, storage)
	policyRepo, _ := policy.NewVaultRepository(ctx, storage)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)

	_, err := NewCryptoOrchestrator(storage, repo, pol, nil, reg)
	if err == nil {
		t.Fatal("expected error for nil provider registry")
	}
}

func TestNewCryptoOrchestrator_nilTemplateRegistry_returnsError(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}

	repo, _ := key.NewVaultRepository(ctx, storage)
	provReg := provider.NewRegistry()
	policyRepo, _ := policy.NewVaultRepository(ctx, storage)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)

	_, err := NewCryptoOrchestrator(storage, repo, pol, provReg, nil)
	if err == nil {
		t.Fatal("expected error for nil template registry")
	}
}

func TestNewCryptoOrchestrator_implementsInterface(t *testing.T) {
	// This test verifies the constructor return type satisfies CryptoOrchestrator
	// by calling a method through the interface.
	ops := setupCryptoOrchestrator(t)
	// Exercise one method to prove ops satisfies CryptoOrchestrator at runtime.
	_, err := ops.GenerateRandom(context.Background(), 16)
	if err == nil {
		t.Fatal("expected CodeNotImplemented from stub")
	}
}
