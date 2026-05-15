package service_test

import (
	"context"
	"testing"

	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
)

// Uses setupOrchestratorFull and helpers from key_create_test.go.

// ============================================================================
// GetKeyWithMaterial Tests
// ============================================================================

func TestGetKeyWithMaterial_latestVersion(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name: "mat-latest", TemplateID: "ml-dsa-65", PolicyID: testPolicyName,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	k, v, err := orch.GetKeyWithMaterial(ctx, created.GetPublicId(), 0) // 0 = latest
	if err != nil {
		t.Fatalf("GetKeyWithMaterial: %v", err)
	}
	if k == nil {
		t.Fatal("returned nil key")
		return // unreachable; satisfies static-analysis nil-flow
	}
	if v == nil {
		t.Fatal("returned nil version")
		return // unreachable; satisfies static-analysis nil-flow
	}
	if k.GetPublicId() != created.GetPublicId() {
		t.Errorf("key PublicId: got %q want %q", k.GetPublicId(), created.GetPublicId())
	}
	if v.GetVersion() != 1 {
		t.Errorf("version: got %d want 1", v.GetVersion())
	}
	if len(v.GetKeyMaterial()) == 0 {
		t.Error("KeyMaterial must not be empty after CreateKey")
	}
	if v.GetProviderId() == "" {
		t.Error("ProviderId must not be empty")
	}
	if v.GetTemplateId() == "" {
		t.Error("TemplateId must not be empty")
	}
}

func TestGetKeyWithMaterial_specificVersion(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name: "mat-specific", TemplateID: "ml-dsa-65", PolicyID: testPolicyName,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	k, v, err := orch.GetKeyWithMaterial(ctx, created.GetPublicId(), 1) // explicit version 1
	if err != nil {
		t.Fatalf("GetKeyWithMaterial: %v", err)
	}
	if k.GetPublicId() != created.GetPublicId() {
		t.Errorf("key PublicId: got %q want %q", k.GetPublicId(), created.GetPublicId())
	}
	if v.GetVersion() != 1 {
		t.Errorf("version: got %d want 1", v.GetVersion())
	}
}

func TestGetKeyWithMaterial_keyNotFound(t *testing.T) {
	orch := setupOrchestrator(t)
	_, _, err := orch.GetKeyWithMaterial(context.Background(), "key_nonexistent", 0)
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected CodeKeyNotFound, got: %v", err)
	}
}

func TestGetKeyWithMaterial_versionNotFound(t *testing.T) {
	orch := setupOrchestrator(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name: "mat-badver", TemplateID: "ml-dsa-65", PolicyID: testPolicyName,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Version 99 does not exist — only version 1 was created.
	_, _, err = orch.GetKeyWithMaterial(ctx, created.GetPublicId(), 99)
	if err == nil {
		t.Fatal("expected error for non-existent version")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected CodeKeyNotFound for missing version, got: %v", err)
	}
}

// TestGetKeyWithMaterial_destroyedKey verifies that a key in a terminal state
// (DESTROYED) is rejected by the IsTerminal() check before version fetch.
func TestGetKeyWithMaterial_destroyedKey_returnsFailedPrecondition(t *testing.T) {
	orch, repo, _ := setupOrchestratorFull(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name: "mat-destroy", TemplateID: "ml-dsa-65", PolicyID: testPolicyName,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Transition to terminal: ACTIVE → COMPROMISED → DESTROYED (per NIST SP 800-57).
	k, err := repo.GetKey(ctx, created.GetPublicId())
	if err != nil {
		t.Fatalf("repo.GetKey: %v", err)
	}
	err = k.TransitionTo(storepb.KeyStatus_KEY_STATUS_COMPROMISED)
	if err != nil {
		t.Fatalf("TransitionTo COMPROMISED: %v", err)
	}
	err = k.TransitionTo(storepb.KeyStatus_KEY_STATUS_DESTROYED)
	if err != nil {
		t.Fatalf("TransitionTo DESTROYED: %v", err)
	}
	err = repo.UpdateKey(ctx, k)
	if err != nil {
		t.Fatalf("repo.UpdateKey: %v", err)
	}

	_, _, err = orch.GetKeyWithMaterial(ctx, created.GetPublicId(), 0)
	if err == nil {
		t.Fatal("expected error for destroyed key")
	}
	if !errors.IsFailedPrecondition(err) {
		t.Errorf("expected CodeFailedPrecondition, got: %v", err)
	}
}

// TestGetKeyWithMaterial_suspendedKey verifies that a non-ACTIVE key
// (SUSPENDED) is rejected by the CanPerformCrypto() check.
func TestGetKeyWithMaterial_suspendedKey_returnsFailedPrecondition(t *testing.T) {
	orch, repo, _ := setupOrchestratorFull(t)
	ctx := context.Background()

	created, err := orch.CreateKey(ctx, core.KeyCreationSpec{
		Name: "mat-suspend", TemplateID: "ml-dsa-65", PolicyID: testPolicyName,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Transition: ACTIVE → SUSPENDED.
	k, err := repo.GetKey(ctx, created.GetPublicId())
	if err != nil {
		t.Fatalf("repo.GetKey: %v", err)
	}
	err = k.TransitionTo(storepb.KeyStatus_KEY_STATUS_SUSPENDED)
	if err != nil {
		t.Fatalf("TransitionTo SUSPENDED: %v", err)
	}
	err = repo.UpdateKey(ctx, k)
	if err != nil {
		t.Fatalf("repo.UpdateKey: %v", err)
	}

	_, _, err = orch.GetKeyWithMaterial(ctx, created.GetPublicId(), 0)
	if err == nil {
		t.Fatal("expected error for suspended key")
	}
	if !errors.IsFailedPrecondition(err) {
		t.Errorf("expected CodeFailedPrecondition, got: %v", err)
	}
}
