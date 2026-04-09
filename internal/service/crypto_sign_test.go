package service_test

import (
	"context"
	"encoding/json"
	"testing"

	types "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/crypto"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/service"
)

// cryptoPolicyName is the name of the policy that allows create_key + sign.
const cryptoPolicyName = "test-crypto-allow"

// seedCryptoPolicy creates a policy that allows ml-dsa-65 with create_key
// and sign operations. Used by setupCryptoWithKey and sign tests.
func seedCryptoPolicy(t *testing.T, ctx context.Context, pol policy.Engine) {
	t.Helper()
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{
				string(core.OperationCreateKey),
				string(core.OperationSign),
			},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	p := policy.NewPolicy("pol_testcrypto", cryptoPolicyName, rulesJSON)
	_, err = pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed crypto policy: %v", err)
	}
}

// setupCryptoWithKey creates a wired CryptoOrchestrator, seeds a policy that
// allows create_key + sign for ml-dsa-65, creates a key, and returns the
// CryptoOrchestrator and the key's public ID.
func setupCryptoWithKey(t *testing.T) (service.CryptoOrchestrator, string) {
	t.Helper()
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

	seedCryptoPolicy(t, ctx, pol)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:       "sign-test-key",
		TemplateID: "ml-dsa-65",
		PolicyID:   cryptoPolicyName,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return ops, created.GetPublicId()
}

// ============================================================================
// Sign Tests
// ============================================================================

func TestSign_MLDSA_happyPath(t *testing.T) {
	ops, keyID := setupCryptoWithKey(t)
	ctx := context.Background()

	result, err := ops.Sign(ctx, crypto.SignRequest{
		KeyPublicID: keyID,
		Payload:     []byte("post-quantum signing"),
		NoContext:   &types.NoParams{},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(result.Signature) == 0 {
		t.Error("expected non-empty signature")
	}
	if result.KeyPublicID != keyID {
		t.Errorf("KeyPublicID: got %q want %q", result.KeyPublicID, keyID)
	}
	if result.Algorithm == "" {
		t.Error("Algorithm must be populated in SignResult")
	}
	if result.ProviderName == "" {
		t.Error("ProviderName must be populated in SignResult")
	}
	if result.KeyVersionID == "" {
		t.Error("KeyVersionID must be populated in SignResult")
	}
}

func TestSign_keyNotFound_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyPublicID: "key_nonexistent",
		Payload:     []byte("data"),
	})
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected CodeKeyNotFound, got: %v", err)
	}
}

func TestSign_emptyKeyPublicID_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyPublicID: "",
		Payload:     []byte("data"),
	})
	if err == nil {
		t.Fatal("expected error for empty KeyPublicID")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSign_emptyPayload_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyPublicID: "key_doesntmatter",
		Payload:     nil,
	})
	if err == nil {
		t.Fatal("expected error for empty Payload")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSign_policyDeniesSign_returnsError(t *testing.T) {
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

	// Seed a policy that allows create_key but NOT sign.
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey)},
		},
	}
	rulesJSON, _ := json.Marshal(rules)
	p := policy.NewPolicy("pol_nosign", "no-sign-policy", rulesJSON)
	_, err := pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// Create key under the restrictive policy.
	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:       "no-sign-key",
		TemplateID: "ml-dsa-65",
		PolicyID:   "no-sign-policy",
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Sign should fail with policy violation.
	_, err = ops.Sign(ctx, crypto.SignRequest{
		KeyPublicID: created.GetPublicId(),
		Payload:     []byte("should fail"),
		NoContext:   &types.NoParams{},
	})
	if err == nil {
		t.Fatal("expected error for policy-denied sign")
	}
	if !errors.IsPolicyViolation(err) {
		t.Errorf("expected CodePolicyViolation, got: %v", err)
	}
}

func TestSign_noScopeParams_returnsError(t *testing.T) {
	ops, keyID := setupCryptoWithKey(t)
	_, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyPublicID: keyID,
		Payload:     []byte("data"),
		// no scope_params set
	})
	if err == nil {
		t.Fatal("expected error when no scope_params are set")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSign_MLDSA_noContext_succeeds(t *testing.T) {
	// The key was created via template ml-dsa-65 whose primary scope is
	// "standard", so NoContext (standard) matches the key's declared scope.
	ops, keyID := setupCryptoWithKey(t)
	result, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyPublicID: keyID,
		Payload:     []byte("standard scope signing"),
		NoContext:   &types.NoParams{},
	})
	if err != nil {
		t.Fatalf("Sign with NoContext on ML-DSA: %v", err)
	}
	if len(result.Signature) == 0 {
		t.Error("expected non-empty signature")
	}
}

func TestSign_scopeMismatch_returnsError(t *testing.T) {
	// Key created via template ml-dsa-65 has primary scope "standard".
	// DomainContext maps to "with_context" — scope mismatch.
	ops, keyID := setupCryptoWithKey(t)
	_, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyPublicID:   keyID,
		Payload:       []byte("data"),
		DomainContext: &types.SignatureDomainContext{},
	})
	if err == nil {
		t.Fatal("expected error for scope mismatch")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSign_multipleScopeParams_returnsError(t *testing.T) {
	// Setting both NoContext and DomainContext violates the oneof contract.
	ops, keyID := setupCryptoWithKey(t)
	_, err := ops.Sign(context.Background(), crypto.SignRequest{
		KeyPublicID:   keyID,
		Payload:       []byte("data"),
		NoContext:     &types.NoParams{},
		DomainContext: &types.SignatureDomainContext{},
	})
	if err == nil {
		t.Fatal("expected error when multiple scope_params are set")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}
