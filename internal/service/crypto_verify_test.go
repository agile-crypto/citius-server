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

// verifyPolicyName is the name of the policy that allows create_key + sign + verify.
const verifyPolicyName = "test-verify-allow"

// seedVerifyPolicy creates a policy that allows ml-dsa-65 with create_key,
// sign, and verify operations. Used by Verify tests that need to sign first.
func seedVerifyPolicy(t *testing.T, ctx context.Context, pol policy.Engine) {
	t.Helper()
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ml-dsa-65"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{
				string(core.OperationCreateKey),
				string(core.OperationSign),
				string(core.OperationVerify),
			},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	p := policy.NewPolicy("pol_testverify", verifyPolicyName, rulesJSON)
	_, err = pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed verify policy: %v", err)
	}
}

// setupCryptoWithKeyForVerify creates a wired CryptoOrchestrator, seeds a
// policy that allows create_key + sign + verify for ml-dsa-65, creates a key,
// and returns the CryptoOrchestrator and the key's public ID.
func setupCryptoWithKeyForVerify(t *testing.T) (service.CryptoOrchestrator, string) {
	t.Helper()
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

	seedVerifyPolicy(t, ctx, pol)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:       "verify-test-key",
		TemplateID: "ml-dsa-65",
		PolicyID:   verifyPolicyName,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return ops, created.GetPublicId()
}

// ============================================================================
// Verify Tests
// ============================================================================

func TestVerify_MLDSA_validSignature_returnsTrue(t *testing.T) {
	ops, keyID := setupCryptoWithKeyForVerify(t)
	ctx := context.Background()
	payload := []byte("post-quantum verification")

	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyPublicID: keyID,
		Payload:     payload,
		NoContext:   &types.NoParams{},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyPublicID: keyID,
		Payload:     payload,
		Signature:   signResult.Signature,
		NoContext:   &types.NoParams{}, // must match signing scope
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("expected valid=true for correct ML-DSA signature")
	}
	if verifyResult.KeyPublicID != keyID {
		t.Errorf("KeyPublicID: got %q want %q", verifyResult.KeyPublicID, keyID)
	}
	if verifyResult.Algorithm == "" {
		t.Error("Algorithm must be populated in VerifyResult")
	}
	if verifyResult.ProviderName == "" {
		t.Error("ProviderName must be populated in VerifyResult")
	}
}

func TestVerify_tamperedPayload_returnsFalse_notError(t *testing.T) {
	ops, keyID := setupCryptoWithKeyForVerify(t)
	ctx := context.Background()

	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyPublicID: keyID,
		Payload:     []byte("original"),
		NoContext:   &types.NoParams{},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyPublicID: keyID,
		Payload:     []byte("tampered"), // different payload
		Signature:   signResult.Signature,
		NoContext:   &types.NoParams{},
	})
	if err != nil {
		t.Fatalf("tampered payload should NOT return error, got: %v", err)
	}
	if verifyResult.Valid {
		t.Error("expected valid=false for tampered payload")
	}
}

func TestVerify_tamperedSignature_returnsFalse_notError(t *testing.T) {
	ops, keyID := setupCryptoWithKeyForVerify(t)
	ctx := context.Background()
	payload := []byte("data")

	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyPublicID: keyID,
		Payload:     payload,
		NoContext:   &types.NoParams{},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	sig := signResult.Signature
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[len(tampered)/2] ^= 0xFF

	verifyResult, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyPublicID: keyID,
		Payload:     payload,
		Signature:   tampered,
		NoContext:   &types.NoParams{},
	})
	if err != nil {
		t.Fatalf("tampered signature should NOT return error, got: %v", err)
	}
	if verifyResult.Valid {
		t.Error("expected valid=false for tampered signature")
	}
}

func TestVerify_keyNotFound_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Verify(context.Background(), crypto.VerifyRequest{
		KeyPublicID: "key_nonexistent",
		Payload:     []byte("data"),
		Signature:   []byte("sig"),
	})
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected CodeKeyNotFound, got: %v", err)
	}
}

func TestVerify_emptyKeyPublicID_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Verify(context.Background(), crypto.VerifyRequest{
		KeyPublicID: "",
		Payload:     []byte("data"),
		Signature:   []byte("sig"),
	})
	if err == nil {
		t.Fatal("expected error for empty KeyPublicID")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestVerify_policyDeniesVerify_returnsError(t *testing.T) {
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

	// Seed a policy that allows create_key + sign but NOT verify.
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
	rulesJSON, _ := json.Marshal(rules)
	p := policy.NewPolicy("pol_noverify", "no-verify-policy", rulesJSON)
	_, err := pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// Create key under the restrictive policy.
	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:       "no-verify-key",
		TemplateID: "ml-dsa-65",
		PolicyID:   "no-verify-policy",
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Sign first (allowed).
	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyPublicID: created.GetPublicId(),
		Payload:     []byte("data"),
		NoContext:   &types.NoParams{},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify should fail with policy violation.
	_, err = ops.Verify(ctx, crypto.VerifyRequest{
		KeyPublicID: created.GetPublicId(),
		Payload:     []byte("data"),
		Signature:   signResult.Signature,
		NoContext:   &types.NoParams{},
	})
	if err == nil {
		t.Fatal("expected error for policy-denied verify")
	}
	if !errors.IsPolicyViolation(err) {
		t.Errorf("expected CodePolicyViolation, got: %v", err)
	}
}

func TestVerify_noScopeParams_returnsError(t *testing.T) {
	ops, keyID := setupCryptoWithKeyForVerify(t)
	_, err := ops.Verify(context.Background(), crypto.VerifyRequest{
		KeyPublicID: keyID,
		Payload:     []byte("data"),
		Signature:   []byte("sig"),
		// no scope_params set
	})
	if err == nil {
		t.Fatal("expected error when no scope_params are set")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestSignVerify_roundTrip_MLDSA65(t *testing.T) {
	ops, keyID := setupCryptoWithKeyForVerify(t)
	ctx := context.Background()
	payload := []byte("canonical round-trip test: ML-DSA-65")

	signResult, err := ops.Sign(ctx, crypto.SignRequest{
		KeyPublicID: keyID,
		Payload:     payload,
		NoContext:   &types.NoParams{},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := ops.Verify(ctx, crypto.VerifyRequest{
		KeyPublicID: keyID,
		Payload:     payload,
		Signature:   signResult.Signature,
		NoContext:   &types.NoParams{}, // must match signing scope
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("round-trip failed: valid=false")
	}
	if verifyResult.KeyPublicID != keyID {
		t.Errorf("KeyPublicID: got %q want %q", verifyResult.KeyPublicID, keyID)
	}
	if verifyResult.Algorithm == "" {
		t.Error("Algorithm must be populated")
	}
	if verifyResult.ProviderName == "" {
		t.Error("ProviderName must be populated")
	}
}

func TestVerify_scopeMismatch_returnsError(t *testing.T) {
	// Key created via template ml-dsa-65 has primary scope "standard".
	// DomainContext maps to "with_context" — scope mismatch.
	ops, keyID := setupCryptoWithKeyForVerify(t)
	_, err := ops.Verify(context.Background(), crypto.VerifyRequest{
		KeyPublicID:   keyID,
		Payload:       []byte("data"),
		Signature:     []byte("sig"),
		DomainContext: &types.SignatureDomainContext{},
	})
	if err == nil {
		t.Fatal("expected error for scope mismatch")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestVerify_multipleScopeParams_returnsError(t *testing.T) {
	// Setting both NoContext and DomainContext violates the oneof contract.
	ops, keyID := setupCryptoWithKeyForVerify(t)
	_, err := ops.Verify(context.Background(), crypto.VerifyRequest{
		KeyPublicID:   keyID,
		Payload:       []byte("data"),
		Signature:     []byte("sig"),
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
