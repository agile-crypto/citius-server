package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/crypto"
	"github.com/agile-crypto/citius-core/policy"
)

// digestSignPolicyName is the name of the policy that allows create_key,
// digest_sign, and digest_verify for ecdsa-p256-sha256-der.
const digestSignPolicyName = "test-digest-sign-allow"

// seedDigestSignPolicy creates a policy that allows ecdsa-p256-sha256-der
// with create_key, digest_sign, and digest_verify operations.
func seedDigestSignPolicy(t *testing.T, ctx context.Context, pol policy.Engine) {
	t.Helper()
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256-der"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{
				string(core.OperationCreateKey),
				string(core.OperationDigestSign),
				string(core.OperationDigestVerify),
			},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	p := policy.NewPolicy("pol_testdigestsign", digestSignPolicyName, rulesJSON)
	_, err = pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed digest-sign policy: %v", err)
	}
}

// setupDigestSignWithKey creates a wired CryptoOrchestrator, seeds a policy
// that allows create_key + digest_sign + digest_verify for
// ecdsa-p256-sha256-der, creates a key, and returns the CryptoOrchestrator
// and the key's name.
//
// ECDSA is used (not ML-DSA) because the software provider's SignDigest is
// currently hard-coded to ECDSA-P256 only — the AlgorithmDetails-based
// dispatch is a later change.
func setupDigestSignWithKey(t *testing.T) (CryptoOrchestrator, string) {
	t.Helper()
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

	seedDigestSignPolicy(t, ctx, pol)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "digest-sign-test-key",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           digestSignPolicyName,
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return ops, created.Name
}

// ============================================================================
// DigestSign / DigestVerify Tests
// ============================================================================

func TestDigestSign_ECDSA_happyPath(t *testing.T) {
	ops, keyName := setupDigestSignWithKey(t)
	ctx := context.Background()

	digest := sha256.Sum256([]byte("pre-hashed by the caller"))

	result, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              keyName,
		Digest:               digest[:],
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}
	if len(result.Signature) == 0 {
		t.Error("expected non-empty signature")
	}
	if result.KeyName != keyName {
		t.Errorf("KeyName: got %q want %q", result.KeyName, keyName)
	}
	if result.Output.GetAlgorithmOutput() == nil {
		t.Error("Output.algorithm_output must be set (provider contract)")
	}
}

func TestDigestSign_DigestVerify_roundtrip(t *testing.T) {
	ops, keyName := setupDigestSignWithKey(t)
	ctx := context.Background()

	digest := sha256.Sum256([]byte("round-trip payload"))

	signResult, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              keyName,
		Digest:               digest[:],
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}

	verifyResult, err := ops.DigestVerify(ctx, crypto.DigestVerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Digest:               digest[:],
		Signature:            signResult.Signature,
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Output:               signResult.Output,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestVerify: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("expected valid=true for a correctly round-tripped digest signature")
	}
}

func TestDigestVerify_tamperedDigest_returnsFalse(t *testing.T) {
	ops, keyName := setupDigestSignWithKey(t)
	ctx := context.Background()

	digest := sha256.Sum256([]byte("original payload"))
	signResult, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              keyName,
		Digest:               digest[:],
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}

	tampered := sha256.Sum256([]byte("tampered payload"))
	verifyResult, err := ops.DigestVerify(ctx, crypto.DigestVerifyRequest{
		KeyName:              keyName,
		KeyVersion:           signResult.KeyVersion,
		Digest:               tampered[:],
		Signature:            signResult.Signature,
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Output:               signResult.Output,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestVerify: %v", err)
	}
	if verifyResult.Valid {
		t.Error("expected valid=false for a tampered digest")
	}
}

func TestDigestSign_keyNotFound_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	ctx := context.Background()

	_, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              "nonexistent-key",
		Digest:               []byte("digest"),
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestDigestSign_emptyDigest_returnsError(t *testing.T) {
	ops, keyName := setupDigestSignWithKey(t)
	ctx := context.Background()

	_, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              keyName,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err == nil {
		t.Fatal("expected error for empty digest")
	}
}

// TestDigestSign_policyDeniesDigestSign_returnsError proves OperationDigestSign
// is a distinct, independently-grantable capability from OperationSign: a
// policy that grants "sign" but not "digest_sign" must deny DigestSign.
func TestDigestSign_policyDeniesDigestSign_returnsError(t *testing.T) {
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)
	ctx := context.Background()

	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256-der"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{string(core.OperationCreateKey), string(core.OperationSign)}, // no digest_sign
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	const signOnlyPolicy = "test-sign-only-no-digest"
	p := policy.NewPolicy("pol_signonly", signOnlyPolicy, rulesJSON)
	if _, err = pol.CreatePolicy(ctx, p); err != nil {
		t.Fatalf("seed sign-only policy: %v", err)
	}

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "sign-only-key",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           signOnlyPolicy,
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	digest := sha256.Sum256([]byte("payload"))
	_, err = ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              created.Name,
		Digest:               digest[:],
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err == nil {
		t.Fatal("expected policy violation: digest_sign not granted by a sign-only policy")
	}
}
