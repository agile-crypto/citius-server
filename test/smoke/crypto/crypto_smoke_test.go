// Package crypto_test contains smoke tests for the Encrypt/Decrypt and
// DigestSign/DigestVerify gRPC handlers, exercised through the real
// grpchandler.Handler and the real software provider — no mocks.
package crypto_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/agile-crypto/ossl-go/ossl"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-server/internal/cmd/server"
	"google.golang.org/protobuf/proto"
)

// catalogPath returns the absolute path to standard_algorithms.json.
func catalogPath() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "..", "proto", "standard_algorithms.json")
}

// buildServer wires a fully functional Handler backed by the real software
// and openssl providers (see server.NewTestableServer), sharing one
// in-memory store between policy seeding and handler calls.
func buildServer(t *testing.T) *server.TestableHandler {
	t.Helper()
	ctx := context.Background()

	h, err := server.NewTestableServer(ctx, server.Config{
		CatalogPath: catalogPath(),
	})
	if err != nil {
		t.Fatalf("NewTestableServer: %v", err)
	}
	return h
}

// activatingFIPSConfig writes a wrapper config that .includes this
// machine's fipsmodule.cnf and activates the fips provider -- the same
// helper internal/provider/openssl's fips_test.go and
// internal/cmd/server's wire_internal_test.go use (duplicated here per
// this codebase's established pattern for this small, unexported,
// per-package helper).
//
// Skips the test if fipsmodule.cnf is absent -- the FIPS module is an
// optional, separately-installed artifact, not something every environment
// running this suite is expected to have.
func activatingFIPSConfig(t *testing.T) string {
	t.Helper()

	moduleConfig := ossl.DefaultFIPSModuleConfig()
	if _, err := os.Stat(moduleConfig); err != nil {
		t.Skipf("FIPS module config not present at %s (openssl fipsinstall not run on this machine): %v", moduleConfig, err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "fips_activate.cnf")
	content := fmt.Sprintf(`openssl_conf = openssl_init

.include %s

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
fips = fips_sect

[default_sect]
activate = 1
`, moduleConfig)

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing FIPS activation config: %v", err)
	}
	return path
}

// seedPolicy creates a policy permitting templates and operations via the
// policy engine in the testable handler's request scope.
func seedPolicy(t *testing.T, ctx context.Context, h *server.TestableHandler, name string, templates, operations []string) string {
	t.Helper()

	type opRule struct {
		KeyOperations []string `json:"key_operations"`
	}
	rules := struct {
		Version           string   `json:"version"`
		AllowedTemplates  []string `json:"allowed_templates"`
		AllowedOperations *opRule  `json:"allowed_operations"`
	}{
		Version:           "1",
		AllowedTemplates:  templates,
		AllowedOperations: &opRule{KeyOperations: operations},
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal policy rules: %v", err)
	}

	if err := h.SeedPolicy(ctx, name, rulesJSON); err != nil {
		t.Fatalf("seed policy %q: %v", name, err)
	}
	return name
}

// createAEADKey creates an aes-256-gcm-128-96 key via the real Handler.
func createAEADKey(t *testing.T, ctx context.Context, h *server.TestableHandler, name, policyName string) string {
	t.Helper()

	templateID := "aes-256-gcm-128-96"
	resp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:   name,
		Policy: policyName,
		ScopeSpec: &typespb.ScopeSpecification{
			ScopeSpec: &typespb.ScopeSpecification_Aead{
				Aead: &typespb.AeadScopeSpec{
					Scope: typespb.AeadScope_AEAD_SCOPE_STANDARD,
				},
			},
		},
		TemplateId: &templateID,
	})
	if err != nil {
		t.Fatalf("CreateKey (AEAD): %v", err)
	}
	if !resp.GetSuccess() {
		t.Fatal("CreateKey (AEAD): success=false")
	}
	return resp.GetKeyMetadata().GetName()
}

// createECDSAKey creates an ecdsa-p256-sha256-der key via the real Handler.
func createECDSAKey(t *testing.T, ctx context.Context, h *server.TestableHandler, name, policyName string) string {
	t.Helper()

	templateID := "ecdsa-p256-sha256-der"
	resp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:   name,
		Policy: policyName,
		ScopeSpec: &typespb.ScopeSpecification{
			ScopeSpec: &typespb.ScopeSpecification_Signature{
				Signature: &typespb.SignatureScopeSpec{
					Scope: typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD,
				},
			},
		},
		TemplateId: &templateID,
	})
	if err != nil {
		t.Fatalf("CreateKey (ECDSA): %v", err)
	}
	if !resp.GetSuccess() {
		t.Fatal("CreateKey (ECDSA): success=false")
	}
	return resp.GetKeyMetadata().GetName()
}

// TestSmoke_Encrypt_Decrypt_AESGCM_RoundTrip exercises the full gRPC handler
// stack for symmetric encryption:
//
//	CreateKey -> Encrypt -> Decrypt -> plaintext identity
func TestSmoke_Encrypt_Decrypt_AESGCM_RoundTrip(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)

	policyName := seedPolicy(t, ctx, h, "aead-allow", []string{"aes-256-gcm-128-96"},
		[]string{"create_key", "encrypt", "decrypt"})
	keyName := createAEADKey(t, ctx, h, "smoke-aead-key", policyName)

	plaintext := []byte("M1 smoke test payload - AES-256-GCM")
	encResp, err := h.CryptoHandler.Encrypt(ctx, &messagespb.EncryptRequest{
		KeyName:   keyName,
		Plaintext: plaintext,
		ScopeParams: &messagespb.EncryptRequest_AeadParams{
			AeadParams: &typespb.AeadEncryptParams{},
		},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(encResp.GetCiphertext()) == 0 {
		t.Fatal("Encrypt returned empty ciphertext")
	}

	decResp, err := h.CryptoHandler.Decrypt(ctx, &messagespb.DecryptRequest{
		KeyName:    keyName,
		Ciphertext: encResp.GetCiphertext(),
		Metadata:   encResp.GetMetadata(),
		ScopeParams: &messagespb.DecryptRequest_AeadParams{
			AeadParams: &typespb.AeadEncryptParams{},
		},
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decResp.GetPlaintext(), plaintext) {
		t.Errorf("Decrypt: plaintext mismatch, got %q want %q", decResp.GetPlaintext(), plaintext)
	}

	t.Log("AES-256-GCM encrypt/decrypt round trip PASSED")
}

// TestSmoke_Decrypt_AESGCM_TamperedCiphertext_Fails proves the AEAD
// authentication tag actually fires through the real Handler and provider —
// a flipped ciphertext byte must fail decryption, not silently succeed with
// garbage plaintext.
func TestSmoke_Decrypt_AESGCM_TamperedCiphertext_Fails(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)

	policyName := seedPolicy(t, ctx, h, "aead-allow", []string{"aes-256-gcm-128-96"},
		[]string{"create_key", "encrypt", "decrypt"})
	keyName := createAEADKey(t, ctx, h, "smoke-aead-key", policyName)

	encResp, err := h.CryptoHandler.Encrypt(ctx, &messagespb.EncryptRequest{
		KeyName:   keyName,
		Plaintext: []byte("M1 smoke test payload - AES-256-GCM"),
		ScopeParams: &messagespb.EncryptRequest_AeadParams{
			AeadParams: &typespb.AeadEncryptParams{},
		},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := make([]byte, len(encResp.GetCiphertext()))
	copy(tampered, encResp.GetCiphertext())
	tampered[0] ^= 0xFF // flip first byte

	_, err = h.CryptoHandler.Decrypt(ctx, &messagespb.DecryptRequest{
		KeyName:    keyName,
		Ciphertext: tampered,
		Metadata:   encResp.GetMetadata(),
		ScopeParams: &messagespb.DecryptRequest_AeadParams{
			AeadParams: &typespb.AeadEncryptParams{},
		},
	})
	if err == nil {
		t.Fatal("Decrypt (tampered ciphertext): expected authentication failure, got no error")
	}

	t.Log("AES-256-GCM tampered ciphertext correctly rejected")
}

// TestSmoke_DigestSign_DigestVerify_ECDSA exercises the full gRPC handler
// stack for prehashed signing:
//
//	CreateKey -> DigestSign -> DigestVerify
func TestSmoke_DigestSign_DigestVerify_ECDSA(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)

	policyName := seedPolicy(t, ctx, h, "ecdsa-digest-allow", []string{"ecdsa-p256-sha256-der"},
		[]string{"create_key", "digest_sign", "digest_verify"})
	keyName := createECDSAKey(t, ctx, h, "smoke-ecdsa-key", policyName)

	digest := sha256.Sum256([]byte("M1 smoke test payload - ECDSA-P256-SHA256 digest sign"))

	digestSignResp, err := h.CryptoHandler.DigestSign(ctx, &messagespb.DigestSignRequest{
		KeyName:       keyName,
		Digest:        digest[:],
		HashAlgorithm: typespb.HashAlgorithm_HASH_ALGORITHM_SHA256,
		ScopeParams: &messagespb.DigestSignRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}
	if len(digestSignResp.GetSignature()) == 0 {
		t.Fatal("DigestSign returned empty signature")
	}

	digestVerifyResp, err := h.CryptoHandler.DigestVerify(ctx, &messagespb.DigestVerifyRequest{
		KeyName:       keyName,
		Digest:        digest[:],
		Signature:     digestSignResp.GetSignature(),
		Metadata:      digestSignResp.GetMetadata(),
		HashAlgorithm: typespb.HashAlgorithm_HASH_ALGORITHM_SHA256,
		ScopeParams: &messagespb.DigestVerifyRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("DigestVerify: %v", err)
	}
	if !digestVerifyResp.GetValid() {
		t.Error("DigestVerify: expected valid=true for correct signature")
	}

	// Negative control: a digest over different data must fail verification.
	wrongDigest := sha256.Sum256([]byte("a different message entirely"))
	digestVerifyBad, err := h.CryptoHandler.DigestVerify(ctx, &messagespb.DigestVerifyRequest{
		KeyName:       keyName,
		Digest:        wrongDigest[:],
		Signature:     digestSignResp.GetSignature(),
		Metadata:      digestSignResp.GetMetadata(),
		HashAlgorithm: typespb.HashAlgorithm_HASH_ALGORITHM_SHA256,
		ScopeParams: &messagespb.DigestVerifyRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("DigestVerify (wrong digest): %v", err)
	}
	if digestVerifyBad.GetValid() {
		t.Error("DigestVerify (wrong digest): expected valid=false")
	}

	t.Log("ECDSA digest sign/verify round trip PASSED")
}

// TestSmoke_CreateKey_providerID_pinned_honoured proves an explicit
// provider_id on CreateKeyRequest is honoured end-to-end through the real
// gRPC handler and proto (de)serialization -- not just at the
// KeyOrchestrator layer (internal/service/key_create_test.go's provider_id
// tests) or the Registry layer (internal/provider/match_test.go's
// fake-provider tests). buildProviderRegistry registers "software" before
// "openssl", so this fails if the pin is silently dropped and registration
// order wins instead.
func TestSmoke_CreateKey_providerID_pinned_honoured(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)

	policyName := seedPolicy(t, ctx, h, "aead-allow", []string{"aes-256-gcm-128-96"},
		[]string{"create_key"})

	templateID := "aes-256-gcm-128-96"
	const providerID = "openssl"
	resp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:       "pinned-key",
		Policy:     policyName,
		ProviderId: providerID,
		ScopeSpec: &typespb.ScopeSpecification{
			ScopeSpec: &typespb.ScopeSpecification_Aead{
				Aead: &typespb.AeadScopeSpec{
					Scope: typespb.AeadScope_AEAD_SCOPE_STANDARD,
				},
			},
		},
		TemplateId: &templateID,
	})
	if err != nil {
		t.Fatalf("CreateKey (pinned to %q): %v", providerID, err)
	}
	if !resp.GetSuccess() {
		t.Fatal("CreateKey: success=false")
	}
	if got := resp.GetKeyMetadata().GetProvider(); got != providerID {
		t.Errorf("CreateKey: provider = %q, want %q — provider_id must be honoured, not overridden by registration order", got, providerID)
	}
}

// TestSmoke_CreateKey_fipsRequired_selectsFIPSInstance proves a scope that
// requires FIPS approval correctly selects the real openssl-fips instance
// over "software" (registered first) through the real gRPC handler — the
// end-to-end path match_test.go's fake-provider FIPS test and
// wire_internal_test.go's direct-Backend-call FIPS test don't individually
// cover, since neither goes through CreateKey -> Match with a real
// multi-provider registry.
func TestSmoke_CreateKey_fipsRequired_selectsFIPSInstance(t *testing.T) {
	ctx := context.Background()
	fipsCfgPath := activatingFIPSConfig(t)

	h, err := server.NewTestableServer(ctx, server.Config{
		CatalogPath:    catalogPath(),
		FIPSConfigPath: fipsCfgPath,
	})
	if err != nil {
		t.Fatalf("NewTestableServer: %v", err)
	}

	policyName := seedPolicy(t, ctx, h, "aead-fips-allow", []string{"aes-256-gcm-128-96"},
		[]string{"create_key"})

	templateID := "aes-256-gcm-128-96"
	resp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:   "fips-key",
		Policy: policyName,
		ScopeSpec: &typespb.ScopeSpecification{
			ScopeSpec: &typespb.ScopeSpecification_Aead{
				Aead: &typespb.AeadScopeSpec{
					Scope: typespb.AeadScope_AEAD_SCOPE_STANDARD,
					Security: &typespb.UniversalSecurityProperties{
						FipsApproved: proto.Bool(true),
					},
				},
			},
		},
		TemplateId: &templateID,
	})
	if err != nil {
		t.Fatalf("CreateKey (FIPS required): %v", err)
	}
	if !resp.GetSuccess() {
		t.Fatal("CreateKey: success=false")
	}
	const wantProvider = "openssl-fips"
	if got := resp.GetKeyMetadata().GetProvider(); got != wantProvider {
		t.Errorf("CreateKey: provider = %q, want %q — a FIPS-required scope must select the FIPS instance, not the first-registered provider", got, wantProvider)
	}
}
