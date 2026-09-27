package crypto_test

import (
	"bytes"
	"context"
	"testing"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-server/internal/cmd/server"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// TestSmoke_MigrateKey_ProviderSwitch_AESGCM moves an AES-GCM key from the
// software provider to the openssl provider with its bytes preserved:
//
//	CreateKey (software) -> Encrypt -> MigrateKey (PROVIDER_SWITCH, openssl)
//	-> Decrypt the pre-migration ciphertext -> Encrypt/Decrypt on openssl
//
// The openssl provider decrypting the ciphertext produced before the
// migration with the new version proves both providers read the same key
// encoding.
func TestSmoke_MigrateKey_ProviderSwitch_AESGCM(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)

	policyName := seedPolicy(t, ctx, h, "aead-migrate", []string{"aes-256-gcm-128-96"},
		[]string{"create_key", "encrypt", "decrypt"})
	keyName := createAEADKey(t, ctx, h, "migrate-aead-key", policyName)

	plaintext := []byte("encrypted before the key moved to openssl")
	aead := &typespb.AeadEncryptParams{}
	before, err := h.CryptoHandler.Encrypt(ctx, &messagespb.EncryptRequest{
		KeyName: keyName, Plaintext: plaintext,
		ScopeParams: &messagespb.EncryptRequest_AeadParams{AeadParams: aead},
	})
	if err != nil {
		t.Fatalf("Encrypt (software): %v", err)
	}

	resp, err := h.KeysHandler.MigrateKey(ctx, &messagespb.MigrateKeyRequest{
		Name:     keyName,
		Target:   &messagespb.MigrateKeyRequest_TargetInstanceId{TargetInstanceId: "openssl"},
		Strategy: messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
	})
	if err != nil {
		t.Fatalf("MigrateKey: %v", err)
	}
	res := resp.GetResult()
	if !resp.GetSuccess() || !res.GetKeyBytesPreserved() {
		t.Fatalf("MigrateKey: success=%v key_bytes_preserved=%v", resp.GetSuccess(), res.GetKeyBytesPreserved())
	}
	if res.GetSourceInstanceId() != "software" || res.GetTargetInstanceId() != "openssl" {
		t.Fatalf("MigrateKey: moved %q -> %q, want software -> openssl", res.GetSourceInstanceId(), res.GetTargetInstanceId())
	}
	md := resp.GetKeyMetadata()
	if md.GetProvider() != "openssl" || md.GetVersion() != 2 || md.GetTemplateId() != "aes-256-gcm-128-96" {
		t.Fatalf("MigrateKey: key at %s v%d template %s, want openssl v2 aes-256-gcm-128-96",
			md.GetProvider(), md.GetVersion(), md.GetTemplateId())
	}

	old, err := h.CryptoHandler.Decrypt(ctx, &messagespb.DecryptRequest{
		KeyName: keyName, Ciphertext: before.GetCiphertext(), Metadata: before.GetMetadata(),
		ScopeParams: &messagespb.DecryptRequest_AeadParams{AeadParams: aead},
	})
	if err != nil {
		t.Fatalf("Decrypt (pre-migration ciphertext): %v", err)
	}
	if !bytes.Equal(old.GetPlaintext(), plaintext) {
		t.Fatalf("Decrypt (pre-migration ciphertext): got %q, want %q", old.GetPlaintext(), plaintext)
	}

	after, err := h.CryptoHandler.Encrypt(ctx, &messagespb.EncryptRequest{
		KeyName: keyName, Plaintext: plaintext,
		ScopeParams: &messagespb.EncryptRequest_AeadParams{AeadParams: aead},
	})
	if err != nil {
		t.Fatalf("Encrypt (openssl): %v", err)
	}
	if got := after.GetMetadata().GetKeyVersion(); got != 2 {
		t.Fatalf("Encrypt after migration used key version %d, want 2", got)
	}
	// The same bytes back version 1, so the software provider decrypts what
	// openssl encrypted.
	crossed := proto.Clone(after.GetMetadata()).(*messagespb.OperationMetadata)
	crossed.KeyVersion = 1
	dec, err := h.CryptoHandler.Decrypt(ctx, &messagespb.DecryptRequest{
		KeyName: keyName, Ciphertext: after.GetCiphertext(), Metadata: crossed,
		ScopeParams: &messagespb.DecryptRequest_AeadParams{AeadParams: aead},
	})
	if err != nil {
		t.Fatalf("Decrypt (openssl ciphertext with software version 1): %v", err)
	}
	if !bytes.Equal(dec.GetPlaintext(), plaintext) {
		t.Fatalf("Decrypt (cross-provider): got %q, want %q", dec.GetPlaintext(), plaintext)
	}
}

// TestSmoke_MigrateKey_RekeyAndArchive_ECDSA moves an ECDSA key to the
// openssl provider with fresh material:
//
//	CreateKey (software) -> Sign -> MigrateKey (REKEY_AND_ARCHIVE, provider
//	type openssl) -> Verify the old signature -> Sign on openssl
//
// The archived version 1 stays on the software provider and keeps verifying
// signatures made before the migration; version 2 is a different key.
func TestSmoke_MigrateKey_RekeyAndArchive_ECDSA(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)

	const templateID = "ecdsa-p256-sha256-der"
	policyName := seedPolicy(t, ctx, h, "ecdsa-migrate", []string{templateID},
		[]string{"create_key", "sign", "verify"})
	keyName := createSignatureKey(t, ctx, h, "migrate-ecdsa-key", policyName, templateID)

	payload := []byte("signed before the key moved to openssl")
	noContext := &typespb.NoParams{}
	sign := func() *messagespb.SignResponse {
		t.Helper()
		resp, err := h.CryptoHandler.Sign(ctx, &messagespb.SignRequest{
			KeyName: keyName, Input: payload,
			ScopeParams: &messagespb.SignRequest_NoContext{NoContext: noContext},
		})
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return resp
	}
	verify := func(sig []byte, md *messagespb.OperationMetadata) bool {
		t.Helper()
		resp, err := h.CryptoHandler.Verify(ctx, &messagespb.VerifyRequest{
			KeyName: keyName, Input: payload, Signature: sig, Metadata: md,
			ScopeParams: &messagespb.VerifyRequest_NoContext{NoContext: noContext},
		})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		return resp.GetValid()
	}

	before := sign()

	resp, err := h.KeysHandler.MigrateKey(ctx, &messagespb.MigrateKeyRequest{
		Name:     keyName,
		Target:   &messagespb.MigrateKeyRequest_ProviderTarget{ProviderTarget: &messagespb.ProviderTarget{ProviderId: "openssl"}},
		Strategy: messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE,
	})
	if err != nil {
		t.Fatalf("MigrateKey: %v", err)
	}
	if res := resp.GetResult(); res.GetKeyBytesPreserved() || res.GetTargetInstanceId() != "openssl" {
		t.Fatalf("MigrateKey: key_bytes_preserved=%v target=%q, want false/openssl", res.GetKeyBytesPreserved(), res.GetTargetInstanceId())
	}
	if archived := resp.GetArchivedKeyInfo(); archived.GetArchivedKeyName() != keyName || archived.GetProviderId() != "software" {
		t.Fatalf("MigrateKey: archived %q on %q, want %q on software", archived.GetArchivedKeyName(), archived.GetProviderId(), keyName)
	}

	if !verify(before.GetSignature(), before.GetMetadata()) {
		t.Fatal("Verify: the pre-migration signature no longer verifies against the archived version")
	}

	after := sign()
	if got := after.GetMetadata().GetKeyVersion(); got != 2 {
		t.Fatalf("Sign after migration used key version %d, want 2", got)
	}
	if !verify(after.GetSignature(), after.GetMetadata()) {
		t.Fatal("Verify: the post-migration signature does not verify")
	}
	// Fresh material: version 1 must not verify what version 2 signed.
	crossed := proto.Clone(after.GetMetadata()).(*messagespb.OperationMetadata)
	crossed.KeyVersion = 1
	if verify(after.GetSignature(), crossed) {
		t.Fatal("Verify: version 1 verified a version 2 signature; the rekey kept the old key")
	}
}

// TestSmoke_MigrateKey_TargetLacksTemplate refuses to migrate a key to a
// provider that does not offer its template (openssl has no prehashed ECDSA
// template), and leaves the key where it was.
func TestSmoke_MigrateKey_TargetLacksTemplate(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)

	policyName := seedPolicy(t, ctx, h, "ecdsa-digest-migrate", []string{"ecdsa-p256-prehashed-der"},
		[]string{"create_key", "read_key"})
	keyName := createECDSAKey(t, ctx, h, "migrate-prehashed-key", policyName)

	_, err := h.KeysHandler.MigrateKey(ctx, &messagespb.MigrateKeyRequest{
		Name:     keyName,
		Target:   &messagespb.MigrateKeyRequest_TargetInstanceId{TargetInstanceId: "openssl"},
		Strategy: messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("MigrateKey: got %v, want NotFound", err)
	}

	read, err := h.KeysHandler.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: keyName})
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if md := read.GetKeyMetadata(); md.GetVersion() != 1 || md.GetProvider() != "software" {
		t.Fatalf("ReadKey: key at %s v%d, want software v1", md.GetProvider(), md.GetVersion())
	}
}

// createSignatureKey creates a standard-scope signature key from templateID.
func createSignatureKey(t *testing.T, ctx context.Context, h *server.TestableHandler, name, policyName, templateID string) string {
	t.Helper()
	resp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:   name,
		Policy: policyName,
		ScopeSpec: &typespb.ScopeSpecification{
			ScopeSpec: &typespb.ScopeSpecification_Signature{
				Signature: &typespb.SignatureScopeSpec{Scope: typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD},
			},
		},
		TemplateId: &templateID,
	})
	if err != nil {
		t.Fatalf("CreateKey (%s): %v", templateID, err)
	}
	return resp.GetKeyMetadata().GetName()
}
