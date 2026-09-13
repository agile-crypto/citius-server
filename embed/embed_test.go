package embed_test

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-server/embed"
)

// catalogPath returns the absolute path to standard_algorithms.json.
func catalogPath() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "proto", "standard_algorithms.json")
}

// TestNew_CreateKey_Sign_Verify proves BuildHandlers/embed produce a real,
// working handler set -- not just one that type-checks -- by driving the
// same CreateKey -> Sign -> Verify path internal/cmd/server's own
// RegisterAll-wired tests exercise, but through Core's direct-call
// accessors instead of a grpc.ServiceRegistrar.
func TestNew_CreateKey_Sign_Verify(t *testing.T) {
	ctx := context.Background()

	core, err := embed.New(ctx, embed.Config{
		CatalogPath: catalogPath(),
		Services: embed.Services{
			KeyManagement: true,
			Crypto:        true,
			CryptoPolicy:  true,
		},
	})
	if err != nil {
		t.Fatalf("embed.New: %v", err)
	}

	policyName := "embed-e2e-allow-ecdsa"
	policyDoc := `{
		"version": "1",
		"allowed_templates": ["ecdsa-p256-sha256-der"],
		"allowed_operations": {"key_operations": ["create_key", "sign", "verify"]}
	}`
	createPolicyResp, err := core.CryptoPolicyHandler().CreateCryptoPolicy(ctx, &messagespb.CreateCryptoPolicyRequest{
		Name:           policyName,
		PolicyDocument: policyDoc,
	})
	if err != nil {
		t.Fatalf("CreateCryptoPolicy: %v", err)
	}
	if !createPolicyResp.GetSuccess() {
		t.Fatalf("CreateCryptoPolicy: success=false")
	}

	templateID := "ecdsa-p256-sha256-der"
	createResp, err := core.KeyManagementHandler().CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:   "embed-e2e-key",
		Policy: policyName,
		ScopeSpec: &typespb.ScopeSpecification{
			ScopeSpec: &typespb.ScopeSpecification_Signature{
				Signature: &typespb.SignatureScopeSpec{Scope: typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD},
			},
		},
		TemplateId: &templateID,
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

	payload := []byte("embed direct-call round-trip payload")
	signResp, err := core.CryptoHandler().Sign(ctx, &messagespb.SignRequest{
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

	verifyResp, err := core.CryptoHandler().Verify(ctx, &messagespb.VerifyRequest{
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

// TestNew_UnselectedServiceIsNil confirms Config.Services actually gates
// which handlers get built -- a service left false must not be silently
// initialized anyway.
func TestNew_UnselectedServiceIsNil(t *testing.T) {
	ctx := context.Background()
	core, err := embed.New(ctx, embed.Config{
		CatalogPath: catalogPath(),
		Services:    embed.Services{KeyManagement: true},
	})
	if err != nil {
		t.Fatalf("embed.New: %v", err)
	}
	if core.KeyManagementHandler() == nil {
		t.Error("KeyManagementHandler: expected non-nil, Services.KeyManagement was true")
	}
	if core.CryptoHandler() != nil {
		t.Error("CryptoHandler: expected nil, Services.Crypto was false")
	}
}
