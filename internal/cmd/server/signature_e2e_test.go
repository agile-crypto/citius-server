package server_test

import (
	"context"
	"testing"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
)

// signatureE2ETemplates lists every signature template reachable through the
// real gRPC Handler's Sign/Verify RPCs (CreateKey -> Sign -> Verify).
//
// Every SIGNATURE_SCOPE_PREHASHED template (ecdsa-*-prehashed-der,
// rsa-pss-*-prehashed, rsa-pkcs1v15-2048-prehashed) and ed25519ph are
// excluded — not as an oversight, but because there is currently no gRPC
// path to reach them at all:
//
//   - A key created with SIGNATURE_SCOPE_PREHASHED can only be used through
//     DigestSign/DigestVerify — validateSignatureScopeParams in
//     crypto_orchestrator_impl.go rejects a full-message Sign call against
//     such a key outright (caller scope "signature_standard" vs. key scope
//     "signature_prehashed"), confirmed empirically: attempting it here
//     returned CodeInvalidArgument.
//   - ed25519ph is rejected by signEd25519 for the same reason from the
//     other direction — it is only reachable via DigestSign, never Sign.
//   - Handler does not implement DigestSign/DigestVerify at all (both fall
//     through to UnimplementedCryptoServiceServer), so none of the above are
//     reachable through any gRPC RPC today.
var signatureE2ETemplates = []string{
	"ecdsa-p256-sha256-der", "ecdsa-p384-sha384-der", "ecdsa-p521-sha512-der",
	"rsa-pss-sha256-mgf1-32-2048", "rsa-pss-sha256-mgf1-32-3072", "rsa-pss-sha384-mgf1-48-4096",
	"rsa-pkcs1v15-sha256-2048",
	"ed25519",
	"ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
}

// TestE2E_AllSignatureTemplates_CreateKey_Sign_Verify exercises the real
// gRPC handler stack — Handler.CreateKey -> Handler.Sign -> Handler.Verify,
// no mocks — for every signature template reachable via Sign/Verify. This is
// the end-to-end analogue of software's
// TestProvider_SupportedAlgorithms_everyEntryMatchesCatalogAndDispatches:
// that test proves the provider's dispatch arms work in isolation; this one
// proves the same algorithms work through the full request path a real
// caller uses — proto (de)serialization, policy enforcement, orchestration,
// key storage/versioning — not just the provider call underneath it.
func TestE2E_AllSignatureTemplates_CreateKey_Sign_Verify(t *testing.T) {
	ctx := context.Background()

	for _, templateID := range signatureE2ETemplates {
		t.Run(templateID, func(t *testing.T) {
			assertCreateKeySignVerifyRoundTrip(t, ctx, templateID)
		})
	}
}

// TestE2E_TransformKey_WithScopeSpecification exercises the real key-management
// handler and verifies that a valid scope-aware transform no longer falls
// through as UNIMPLEMENTED. The transformed version must also be immediately
// usable by the crypto handler.
func TestE2E_TransformKey_WithScopeSpecification(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	policyName := seedPolicy(t, ctx, h, "e2e-transform-allow", []string{
		"ecdsa-p256-sha256-der",
		"ml-dsa-65",
	})

	scopeSpec := &typespb.ScopeSpecification{
		ScopeSpec: &typespb.ScopeSpecification_Signature{
			Signature: &typespb.SignatureScopeSpec{
				Scope: typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD,
			},
		},
	}
	initialTemplate := "ecdsa-p256-sha256-der"
	createResp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:       "e2e-transform-key",
		Policy:     policyName,
		ProviderId: "software",
		ScopeSpec:  scopeSpec,
		TemplateId: &initialTemplate,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	targetTemplate := "ml-dsa-65"
	transformResp, err := h.KeysHandler.TransformKey(ctx, &messagespb.TransformKeyRequest{
		Name:       createResp.GetKeyMetadata().GetName(),
		ScopeSpec:  scopeSpec,
		TemplateId: &targetTemplate,
	})
	if err != nil {
		t.Fatalf("TransformKey: %v", err)
	}
	metadata := transformResp.GetKeyMetadata()
	if !transformResp.GetSuccess() {
		t.Fatal("TransformKey: success=false")
	}
	if metadata.GetVersion() != 2 {
		t.Fatalf("TransformKey version: got %d, want 2", metadata.GetVersion())
	}
	if metadata.GetTemplateId() != targetTemplate {
		t.Fatalf("TransformKey template: got %q, want %q", metadata.GetTemplateId(), targetTemplate)
	}
	if metadata.GetScopeSpec().GetSignature().GetScope() != typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD {
		t.Fatalf("TransformKey scope: got %v, want SIGNATURE_SCOPE_STANDARD", metadata.GetScopeSpec())
	}

	payload := []byte("end-to-end transformed ML-DSA signature")
	signResp, err := h.CryptoHandler.Sign(ctx, &messagespb.SignRequest{
		KeyName:     metadata.GetName(),
		Input:       payload,
		ScopeParams: &messagespb.SignRequest_NoContext{NoContext: &typespb.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign transformed key: %v", err)
	}
	if signResp.GetMetadata().GetKeyVersion() != 2 {
		t.Fatalf("Sign key version: got %d, want 2", signResp.GetMetadata().GetKeyVersion())
	}

	verifyResp, err := h.CryptoHandler.Verify(ctx, &messagespb.VerifyRequest{
		KeyName:     metadata.GetName(),
		Input:       payload,
		Signature:   signResp.GetSignature(),
		Metadata:    signResp.GetMetadata(),
		ScopeParams: &messagespb.VerifyRequest_NoContext{NoContext: &typespb.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify transformed key: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Fatal("Verify transformed key: valid=false")
	}
}

// assertCreateKeySignVerifyRoundTrip creates a key for templateID, signs a
// fixed payload, and verifies it — all through the real gRPC Handler.
func assertCreateKeySignVerifyRoundTrip(t *testing.T, ctx context.Context, templateID string) {
	t.Helper()
	h := buildServer(t)
	policyName := seedPolicy(t, ctx, h, "e2e-allow-"+templateID, []string{templateID})

	tmplID := templateID
	createResp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:   "e2e-key",
		Policy: policyName,
		ScopeSpec: &typespb.ScopeSpecification{
			ScopeSpec: &typespb.ScopeSpecification_Signature{
				Signature: &typespb.SignatureScopeSpec{Scope: typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD},
			},
		},
		TemplateId: &tmplID,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if !createResp.GetSuccess() {
		t.Fatalf("CreateKey: success=false")
	}
	keyName := createResp.GetKeyMetadata().GetName()
	if keyName == "" {
		t.Fatal("CreateKey returned empty key name")
	}

	payload := []byte("end-to-end signature round-trip payload: " + templateID)
	signResp, err := h.CryptoHandler.Sign(ctx, &messagespb.SignRequest{
		KeyName:     keyName,
		Input:       payload,
		ScopeParams: &messagespb.SignRequest_NoContext{NoContext: &typespb.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signResp.GetSignature()) == 0 {
		t.Fatal("Sign returned empty signature")
	}

	verifyResp, err := h.CryptoHandler.Verify(ctx, &messagespb.VerifyRequest{
		KeyName:     keyName,
		Input:       payload,
		Signature:   signResp.GetSignature(),
		Metadata:    signResp.GetMetadata(),
		ScopeParams: &messagespb.VerifyRequest_NoContext{NoContext: &typespb.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("Verify: expected valid=true for a signature just produced by Sign")
	}
}
