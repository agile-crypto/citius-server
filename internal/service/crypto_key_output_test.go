package service

import (
	"context"
	"encoding/json"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/crypto"
	"github.com/agile-crypto/citius-server/internal/key"
	"github.com/agile-crypto/citius-server/internal/policy"
	"github.com/agile-crypto/citius-server/internal/provider"
	"github.com/agile-crypto/citius-server/internal/provider/software"
	"github.com/agile-crypto/citius-server/internal/template"
	"github.com/hashicorp/vault/sdk/logical"
)

// capturingSigner wraps the real software provider, recording the last
// SignRequest/SignDigestRequest/EncryptRequest/DecryptRequest it receives —
// including fields (like key_material_encoding) — so tests can verify
// exactly what the orchestrator sends without depending on provider behavior
// that hasn't been wired up.
type capturingSigner struct {
	*software.Provider
	lastSignRequest       *providerpb.SignRequest
	lastSignDigestRequest *providerpb.SignDigestRequest
	lastEncryptRequest    *providerpb.EncryptRequest
	lastDecryptRequest    *providerpb.DecryptRequest
}

func (c *capturingSigner) Sign(ctx context.Context, req *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	c.lastSignRequest = req
	return c.Provider.Sign(ctx, req)
}

func (c *capturingSigner) SignDigest(ctx context.Context, req *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	c.lastSignDigestRequest = req
	return c.Provider.SignDigest(ctx, req)
}

func (c *capturingSigner) Encrypt(ctx context.Context, req *providerpb.EncryptRequest) (*providerpb.EncryptResponse, error) {
	c.lastEncryptRequest = req
	return c.Provider.Encrypt(ctx, req)
}

func (c *capturingSigner) Decrypt(ctx context.Context, req *providerpb.DecryptRequest) (*providerpb.DecryptResponse, error) {
	c.lastDecryptRequest = req
	return c.Provider.Decrypt(ctx, req)
}

var (
	_ provider.Backend = (*capturingSigner)(nil)
	_ provider.Signer  = (*capturingSigner)(nil)
	_ provider.Cipher  = (*capturingSigner)(nil)
)

// setupWithCapturingSigner mirrors setupCryptoOrchestratorFull but registers
// a capturingSigner instead of a plain software.Provider, so the test can
// inspect the provider-level requests the orchestrator builds.
func setupWithCapturingSigner(t *testing.T) (CryptoOrchestrator, KeyOrchestrator, *capturingSigner) {
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
	if err = template.LoadStandardCatalog(ctx, catalogPath(), reg); err != nil {
		t.Fatalf("LoadStandardCatalog: %v", err)
	}

	sig := &capturingSigner{Provider: software.New()}
	provReg := provider.NewRegistry()
	if err = provReg.Register(ctx, sig); err != nil {
		t.Fatalf("Register provider: %v", err)
	}

	policyRepo, err := policy.NewVaultRepository(ctx, storage)
	if err != nil {
		t.Fatalf("policy.NewVaultRepository: %v", err)
	}
	pol, err := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	rules := &policy.Rules{
		Version:          "1",
		AllowedTemplates: []string{"ecdsa-p256-sha256-der", "aes-256-gcm-128-96"},
		AllowedOperations: &policy.OperationRule{
			KeyOperations: []string{
				string(core.OperationCreateKey),
				string(core.OperationSign),
				string(core.OperationDigestSign),
				string(core.OperationEncrypt),
				string(core.OperationDecrypt),
			},
		},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	const policyName = "test-key-output-allow"
	p := policy.NewPolicy("pol_keyoutput", policyName, rulesJSON)
	if _, err = pol.CreatePolicy(ctx, p); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	keyOrch, err := NewKeyOrchestrator(repo, reg, provReg, pol)
	if err != nil {
		t.Fatalf("NewKeyOrchestrator: %v", err)
	}
	ops, err := NewCryptoOrchestrator(repo, pol, provReg, reg)
	if err != nil {
		t.Fatalf("NewCryptoOrchestrator: %v", err)
	}

	if _, err = keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "key-output-test-key",
		TemplateID:         "ecdsa-p256-sha256-der",
		PolicyID:           policyName,
		ScopeSpecification: defaultScopeSpec(t),
	}); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	if _, err = keyOrch.CreateKey(ctx, core.KeyCreationSpec{
		Name:               "key-output-test-cipher-key",
		TemplateID:         "aes-256-gcm-128-96",
		PolicyID:           policyName,
		ScopeSpecification: scopeSpecWithScope(t, core.ScopeAeadStandard),
	}); err != nil {
		t.Fatalf("CreateKey (cipher): %v", err)
	}

	return ops, keyOrch, sig
}

func TestSign_threadsKeyEncodingFromStoredGenerateKeyResponse(t *testing.T) {
	ops, _, sig := setupWithCapturingSigner(t)
	ctx := context.Background()

	_, err := ops.Sign(ctx, crypto.SignRequest{
		KeyName:              "key-output-test-key",
		Payload:              []byte("payload"),
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if sig.lastSignRequest == nil {
		t.Fatal("provider never received a SignRequest")
	}
	// ECDSA private half: x509.MarshalECPrivateKey (SEC1, RFC 5915) — see provider.go.
	want := providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1
	if got := sig.lastSignRequest.GetKeyMaterialEncoding(); got != want {
		t.Errorf("SignRequest.key_material_encoding = %s, want %s — GenerateKeyResponse encoding was not threaded through", got, want)
	}
}

func TestDigestSign_threadsKeyEncodingFromStoredGenerateKeyResponse(t *testing.T) {
	ops, _, sig := setupWithCapturingSigner(t)
	ctx := context.Background()

	_, err := ops.DigestSign(ctx, crypto.DigestSignRequest{
		KeyName:              "key-output-test-key",
		Digest:               make([]byte, 32),
		HashAlgorithm:        types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScopeFields: crypto.SignatureScopeFields{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}

	if sig.lastSignDigestRequest == nil {
		t.Fatal("provider never received a SignDigestRequest")
	}
	want := providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1
	if got := sig.lastSignDigestRequest.GetKeyMaterialEncoding(); got != want {
		t.Errorf("SignDigestRequest.key_material_encoding = %s, want %s — GenerateKeyResponse encoding was not threaded through", got, want)
	}
}

// TestEncrypt_threadsKeyEncodingFromStoredGenerateKeyResponse and
// TestDecrypt_threadsKeyEncodingFromStoredGenerateKeyResponse are the
// Encrypt/Decrypt analogues of TestSign_threadsKeyEncodingFromStoredGenerateKeyResponse
// — until EncryptRequest/DecryptRequest gained a key_material_encoding
// field, there was no field for the orchestrator to thread this through at
// all; these guard against that regressing.
func TestEncrypt_threadsKeyEncodingFromStoredGenerateKeyResponse(t *testing.T) {
	ops, _, sig := setupWithCapturingSigner(t)
	ctx := context.Background()

	_, err := ops.Encrypt(ctx, crypto.EncryptRequest{
		KeyName:               "key-output-test-cipher-key",
		Plaintext:             []byte("payload"),
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{}},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if sig.lastEncryptRequest == nil {
		t.Fatal("provider never received an EncryptRequest")
	}
	// AES-GCM key material: raw bytes, no PKCS8/SEC1/SPKI structure — see generateSymmetricKey.
	want := providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW
	if got := sig.lastEncryptRequest.GetKeyMaterialEncoding(); got != want {
		t.Errorf("EncryptRequest.key_material_encoding = %s, want %s — GenerateKeyResponse encoding was not threaded through", got, want)
	}
}

func TestDecrypt_threadsKeyEncodingFromStoredGenerateKeyResponse(t *testing.T) {
	ops, _, sig := setupWithCapturingSigner(t)
	ctx := context.Background()

	encResult, err := ops.Encrypt(ctx, crypto.EncryptRequest{
		KeyName:               "key-output-test-cipher-key",
		Plaintext:             []byte("payload"),
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{}},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = ops.Decrypt(ctx, crypto.DecryptRequest{
		KeyName:               "key-output-test-cipher-key",
		KeyVersion:            encResult.KeyVersion,
		Ciphertext:            encResult.Ciphertext,
		Output:                encResult.Output,
		EncryptionScopeFields: crypto.EncryptionScopeFields{AeadParams: &types.AeadEncryptParams{}},
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if sig.lastDecryptRequest == nil {
		t.Fatal("provider never received a DecryptRequest")
	}
	want := providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW
	if got := sig.lastDecryptRequest.GetKeyMaterialEncoding(); got != want {
		t.Errorf("DecryptRequest.key_material_encoding = %s, want %s — GenerateKeyResponse encoding was not threaded through", got, want)
	}
}
