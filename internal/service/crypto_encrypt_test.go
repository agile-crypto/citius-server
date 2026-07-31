package service

import (
	"context"
	"encoding/json"
	"testing"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	"github.com/agile-crypto/citius-server/internal/core"
	"github.com/agile-crypto/citius-server/internal/crypto"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/policy"
)

// encryptPolicyName is the name of the policy that allows create_key + encrypt + decrypt.
const encryptPolicyName = "test-encrypt-allow"

// seedEncryptPolicy creates a policy that allows aes-256-gcm-128-96 with
// create_key, encrypt, and decrypt operations.
func seedEncryptPolicy(t *testing.T, ctx context.Context, pol policy.Engine) {
	t.Helper()
	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"aes-256-gcm-128-96"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{
				string(core.OperationCreateKey),
				string(core.OperationEncrypt),
				string(core.OperationDecrypt),
			},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	p := policy.NewPolicy("pol_testencrypt", encryptPolicyName, rulesJSON)
	_, err = pol.CreatePolicy(ctx, p)
	if err != nil {
		t.Fatalf("seed encrypt policy: %v", err)
	}
}

// setupCryptoWithKeyForEncrypt creates a wired CryptoOrchestrator, seeds a
// policy that allows create_key + encrypt + decrypt for aes-256-gcm-128-96,
// creates a key, and returns the CryptoOrchestrator and the key's name.
func setupCryptoWithKeyForEncrypt(t *testing.T) (CryptoOrchestrator, string) {
	t.Helper()
	ctx := context.Background()
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)

	seedEncryptPolicy(t, ctx, pol)

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "encrypt-test-key",
		TemplateID:         "aes-256-gcm-128-96",
		PolicyID:           encryptPolicyName,
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeAeadStandard),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return ops, created.Name
}

// ============================================================================
// Encrypt / Decrypt Tests
// ============================================================================

func TestEncryptDecrypt_AESGCM_roundTrip(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForEncrypt(t)
	ctx := context.Background()
	plaintext := []byte("orchestrated AES-256-GCM round trip")

	encResult, err := ops.Encrypt(ctx, crypto.EncryptRequest{
		KeyName:               keyName,
		Plaintext:             plaintext,
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{}},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(encResult.Ciphertext) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}
	if encResult.Output.GetAeadOutput().GetNonce() == nil {
		t.Fatal("expected a system-generated nonce in Output")
	}

	decResult, err := ops.Decrypt(ctx, crypto.DecryptRequest{
		KeyName:               keyName,
		KeyVersion:            encResult.KeyVersion,
		Ciphertext:            encResult.Ciphertext,
		Output:                encResult.Output,
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{}},
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decResult.Plaintext) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", decResult.Plaintext, plaintext)
	}
	if decResult.Algorithm != "aes-256-gcm-128-96" {
		t.Errorf("Algorithm = %q, want %q", decResult.Algorithm, "aes-256-gcm-128-96")
	}
}

func TestEncryptDecrypt_AESGCM_withAAD_roundTrip(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForEncrypt(t)
	ctx := context.Background()
	plaintext := []byte("payload")
	aad := []byte("associated authenticated data")

	encResult, err := ops.Encrypt(ctx, crypto.EncryptRequest{
		KeyName:               keyName,
		Plaintext:             plaintext,
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{Aad: aad}},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decResult, err := ops.Decrypt(ctx, crypto.DecryptRequest{
		KeyName:               keyName,
		KeyVersion:            encResult.KeyVersion,
		Ciphertext:            encResult.Ciphertext,
		Output:                encResult.Output,
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{Aad: aad}},
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decResult.Plaintext) != string(plaintext) {
		t.Errorf("round-trip mismatch with AAD: got %q, want %q", decResult.Plaintext, plaintext)
	}
}

func TestDecrypt_AESGCM_wrongAAD_returnsError(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForEncrypt(t)
	ctx := context.Background()

	encResult, err := ops.Encrypt(ctx, crypto.EncryptRequest{
		KeyName:               keyName,
		Plaintext:             []byte("payload"),
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{Aad: []byte("original")}},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = ops.Decrypt(ctx, crypto.DecryptRequest{
		KeyName:               keyName,
		KeyVersion:            encResult.KeyVersion,
		Ciphertext:            encResult.Ciphertext,
		Output:                encResult.Output,
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{Aad: []byte("wrong")}},
	})
	if err == nil {
		t.Fatal("expected error for mismatched AAD")
	}
}

func TestEncrypt_emptyKeyName_returnsError(t *testing.T) {
	ops := setupCryptoOrchestrator(t)
	_, err := ops.Encrypt(context.Background(), crypto.EncryptRequest{
		Plaintext:             []byte("payload"),
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{}},
	})
	if err == nil {
		t.Fatal("expected error for empty KeyName")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestEncrypt_emptyPlaintext_returnsError(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForEncrypt(t)
	_, err := ops.Encrypt(context.Background(), crypto.EncryptRequest{
		KeyName:               keyName,
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{}},
	})
	if err == nil {
		t.Fatal("expected error for empty Plaintext")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestDecrypt_emptyCiphertext_returnsError(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForEncrypt(t)
	_, err := ops.Decrypt(context.Background(), crypto.DecryptRequest{
		KeyName:               keyName,
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{}},
	})
	if err == nil {
		t.Fatal("expected error for empty Ciphertext")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

// TestEncrypt_scopeParamsMismatch_returnsError proves the encryption analogue
// of validateSignatureScopeParams: a caller declaring NoParams against a key
// provisioned with ScopeAeadStandard is rejected — mirroring how a signature
// call with the wrong SignatureScopeFields variant is rejected.
func TestEncrypt_scopeParamsMismatch_returnsError(t *testing.T) {
	ops, keyName := setupCryptoWithKeyForEncrypt(t)
	_, err := ops.Encrypt(context.Background(), crypto.EncryptRequest{
		KeyName:               keyName,
		Plaintext:             []byte("payload"),
		EncryptionScopeFields: crypto.EncryptionScopeFields{NoParams: &types.NoParams{}},
	})
	if err == nil {
		t.Fatal("expected error for NoParams scope against an AEAD-scoped key")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestEncrypt_unsupportedTemplate_returnsError(t *testing.T) {
	ops, keyOrch, pol := setupCryptoOrchestratorFull(t)
	ctx := context.Background()
	seedVerifyPolicy(t, ctx, pol) // allows ml-dsa-65, not encryption

	created, err := keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "sign-only-key",
		TemplateID:         "ml-dsa-65",
		PolicyID:           verifyPolicyName,
		ScopeSpecification: defaultScopeSpec(t),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	_, err = ops.Encrypt(ctx, crypto.EncryptRequest{
		KeyName:               created.Name,
		Plaintext:             []byte("payload"),
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{}},
	})
	if err == nil {
		t.Fatal("expected error: policy does not allow encrypt for ml-dsa-65")
	}
}
