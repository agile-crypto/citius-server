package service_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/citius-core/service"

	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/storage"
	"github.com/agile-crypto/citius-core/template"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

// ============================================================================
// Shared Crypto Orchestrator Setup
// ============================================================================

// setupCryptoOrchestratorFull creates a fully wired service.CryptoOrchestrator backed
// by in-memory storage, the software provider, and the standard algorithm
// catalog. It returns the service.CryptoOrchestrator, service.KeyOrchestrator (for creating
// keys in tests), and policy.Engine (for seeding custom policies).
func setupCryptoOrchestratorFull(t *testing.T) (service.CryptoOrchestrator, service.KeyOrchestrator, policy.Engine) {
	t.Helper()
	ctx := context.Background()
	store := &storage.InmemStorage{}

	repo, err := key.NewStorageRepository(ctx, store)
	if err != nil {
		t.Fatalf("NewStorageRepository: %v", err)
	}

	reg, err := template.NewVaultRegistry(ctx, store)
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

	policyRepo, err := policy.NewStorageRepository(ctx, store)
	if err != nil {
		t.Fatalf("policy.NewStorageRepository: %v", err)
	}
	eval := policy.NewSimpleRulesEvaluator()
	pol, err := policy.NewEnforcer(policyRepo, eval)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	keyOrch, err := service.NewKeyOrchestrator(repo, reg, provReg, pol)
	if err != nil {
		t.Fatalf("service.NewKeyOrchestrator: %v", err)
	}

	ops, err := service.NewCryptoOrchestrator(repo, pol, provReg, reg)
	if err != nil {
		t.Fatalf("service.NewCryptoOrchestrator: %v", err)
	}
	return ops, keyOrch, pol
}

// setupCryptoOrchestrator is a convenience wrapper that returns only the
// service.CryptoOrchestrator. Use setupCryptoOrchestratorFull when you also need
// the service.KeyOrchestrator or policy.Engine.
func setupCryptoOrchestrator(t *testing.T) service.CryptoOrchestrator {
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
		t.Fatal("service.NewCryptoOrchestrator returned nil")
	}
}

func TestNewCryptoOrchestrator_nilKeyReader_returnsError(t *testing.T) {
	ctx := context.Background()
	store := &storage.InmemStorage{}

	reg, _ := template.NewVaultRegistry(ctx, store)
	provReg := provider.NewRegistry()
	policyRepo, _ := policy.NewStorageRepository(ctx, store)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)

	_, err := service.NewCryptoOrchestrator(nil, pol, provReg, reg)
	if err == nil {
		t.Fatal("expected error for nil key reader")
	}
}

func TestNewCryptoOrchestrator_nilPolicyEngine_returnsError(t *testing.T) {
	ctx := context.Background()
	store := &storage.InmemStorage{}

	repo, _ := key.NewStorageRepository(ctx, store)
	reg, _ := template.NewVaultRegistry(ctx, store)
	provReg := provider.NewRegistry()

	_, err := service.NewCryptoOrchestrator(repo, nil, provReg, reg)
	if err == nil {
		t.Fatal("expected error for nil policy engine")
	}
}

func TestNewCryptoOrchestrator_nilProviderRegistry_returnsError(t *testing.T) {
	ctx := context.Background()
	store := &storage.InmemStorage{}

	repo, _ := key.NewStorageRepository(ctx, store)
	reg, _ := template.NewVaultRegistry(ctx, store)
	policyRepo, _ := policy.NewStorageRepository(ctx, store)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)

	_, err := service.NewCryptoOrchestrator(repo, pol, nil, reg)
	if err == nil {
		t.Fatal("expected error for nil provider registry")
	}
}

func TestNewCryptoOrchestrator_nilTemplateRegistry_returnsError(t *testing.T) {
	ctx := context.Background()
	store := &storage.InmemStorage{}

	repo, _ := key.NewStorageRepository(ctx, store)
	provReg := provider.NewRegistry()
	policyRepo, _ := policy.NewStorageRepository(ctx, store)
	eval := policy.NewSimpleRulesEvaluator()
	pol, _ := policy.NewEnforcer(policyRepo, eval)

	_, err := service.NewCryptoOrchestrator(repo, pol, provReg, nil)
	if err == nil {
		t.Fatal("expected error for nil template registry")
	}
}

func TestNewCryptoOrchestrator_implementsInterface(t *testing.T) {
	// This test verifies the constructor return type satisfies service.CryptoOrchestrator
	// by calling a method through the interface.
	ops := setupCryptoOrchestrator(t)
	// Exercise one method to prove ops satisfies service.CryptoOrchestrator at runtime.
	_, err := ops.GenerateRandom(context.Background(), 16)
	if err == nil {
		t.Fatal("expected CodeNotImplemented from stub")
	}
}
