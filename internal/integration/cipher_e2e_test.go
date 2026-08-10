package integration_test

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/protobuf/proto"

	messages "github.com/agile-crypto/citius-server/gen/go/api/messages"
	api "github.com/agile-crypto/citius-server/gen/go/api/types"
	"github.com/agile-crypto/citius-server/internal/core"
	"github.com/agile-crypto/citius-server/internal/crypto"
)

// cipherE2ETemplates lists every cipher template this test exercises through
// the full orchestration stack (app.Service -> RequestScope ->
// CryptoOrchestrator -> KeyOrchestrator -> ProviderRegistry ->
// software.Provider), paired with the scope its catalog entry declares and
// whether that scope requires AeadParams (GCM, ChaCha20-Poly1305/XChaCha20)
// or NoParams (CBC, CTR) — see validateEncryptionScopeParams.
var cipherE2ETemplates = []struct {
	templateID string
	scope      core.Scope
	aead       bool
}{
	{"aes-128-gcm-128-96", core.ScopeAeadStandard, true},
	{"aes-192-gcm-128-96", core.ScopeAeadStandard, true},
	{"aes-256-gcm-128-96", core.ScopeAeadStandard, true},
	{"aes-128-cbc-pkcs7-128", core.ScopeSymmetricCipherBlock, false},
	{"aes-192-cbc-pkcs7-128", core.ScopeSymmetricCipherBlock, false},
	{"aes-256-cbc-pkcs7-128", core.ScopeSymmetricCipherBlock, false},
	{"aes-128-ctr", core.ScopeSymmetricCipherStream, false},
	{"aes-192-ctr", core.ScopeSymmetricCipherStream, false},
	{"aes-256-ctr", core.ScopeSymmetricCipherStream, false},
	{"chacha20-poly1305", core.ScopeAeadStandard, true},
	{"xchacha20-poly1305", core.ScopeAeadStandard, true},
}

// TestE2E_AllCipherTemplates_CreateKey_Encrypt_Decrypt exercises the full
// orchestration stack for every cipher template the software provider
// implements — the encrypt/decrypt analogue of software's
// TestProvider_SupportedAlgorithms_everyEntryMatchesCatalogAndDispatches
// (provider-only dispatch coverage) and internal/cmd/server's
// TestE2E_AllSignatureTemplates_CreateKey_Sign_Verify (the gRPC Handler
// implements Sign/Verify but not Encrypt/Decrypt at all — both currently
// fall through to UnimplementedCryptoServiceServer — so this test stops one
// layer short of gRPC, at the same CryptoOrchestrator layer
// TestIntegration_Software_ECDSA_RoundTrip already exercises).
//
// It also proves metadata replay: EncryptResult.Output (the
// system-generated nonce/IV) is proto-marshaled and unmarshaled before being
// passed to Decrypt, simulating what a real caller does — store the opaque
// metadata bytes Encrypt returned, then present them again, unmodified, in
// a later, independent Decrypt call — rather than reusing the same
// in-memory object Encrypt produced.
func TestE2E_AllCipherTemplates_CreateKey_Encrypt_Decrypt(t *testing.T) {
	for _, tc := range cipherE2ETemplates {
		t.Run(tc.templateID, func(t *testing.T) {
			assertCreateKeyEncryptDecryptRoundTrip(t, tc.templateID, tc.scope, tc.aead)
		})
	}
}

// assertCreateKeyEncryptDecryptRoundTrip creates a key for templateID,
// encrypts a fixed payload, and decrypts it — all through the full
// orchestration stack, with the ciphertext's ProviderOutput proto-replayed
// between the two calls (see replayProviderOutput).
func assertCreateKeyEncryptDecryptRoundTrip(t *testing.T, templateID string, scope core.Scope, aead bool) {
	t.Helper()
	svc := wireWithSoftwareProvider(t)
	ctx := context.Background()
	store := &logical.InmemStorage{}

	requestScope, err := svc.ForStorage(ctx, store)
	if err != nil {
		t.Fatalf("ForStorage: %v", err)
	}

	policyName := seedPolicy(t, ctx, requestScope.Policy(),
		"e2e-cipher-allow-"+templateID,
		[]string{templateID},
		[]core.Operation{core.OperationCreateKey, core.OperationEncrypt, core.OperationDecrypt},
	)

	createdKey, err := requestScope.Keys().CreateKey(ctx, core.KeyCreationSpec{
		Name:               "e2e-cipher-key",
		TemplateID:         templateID,
		PolicyID:           policyName,
		ScopeSpecification: &core.ScopeSpecification{Scope: scope},
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	scopeFields := crypto.EncryptionScopeFields{NoParams: &api.NoParams{}}
	if aead {
		scopeFields = crypto.EncryptionScopeFields{AeadParams: &api.AeadEncryptParams{}}
	}

	plaintext := []byte("end-to-end cipher round-trip payload: " + templateID)
	encResult, err := requestScope.Crypto().Encrypt(ctx, crypto.EncryptRequest{
		KeyName:               createdKey.Name,
		Plaintext:             plaintext,
		EncryptionScopeFields: scopeFields,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(encResult.Ciphertext) == 0 {
		t.Fatal("Encrypt returned empty ciphertext")
	}

	replayedOutput := replayProviderOutput(t, encResult.Output)

	decResult, err := requestScope.Crypto().Decrypt(ctx, crypto.DecryptRequest{
		KeyName:               createdKey.Name,
		KeyVersion:            encResult.KeyVersion,
		Ciphertext:            encResult.Ciphertext,
		Output:                replayedOutput,
		EncryptionScopeFields: scopeFields,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decResult.Plaintext) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", decResult.Plaintext, plaintext)
	}
}

// replayProviderOutput proto-marshals then unmarshals a ProviderOutput,
// simulating a caller storing it (e.g. in a database) and presenting it
// again, unmodified, in a later request — rather than reusing the exact
// in-memory object Encrypt returned.
func replayProviderOutput(t *testing.T, output *messages.ProviderOutput) *messages.ProviderOutput {
	t.Helper()
	data, err := proto.Marshal(output)
	if err != nil {
		t.Fatalf("proto.Marshal(Output): %v", err)
	}
	replayed := &messages.ProviderOutput{}
	if err := proto.Unmarshal(data, replayed); err != nil {
		t.Fatalf("proto.Unmarshal(Output): %v", err)
	}
	return replayed
}
