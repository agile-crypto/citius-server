package server_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	messagespb "github.ibm.com/citius/citius-server/gen/go/messages"
	typespb "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/cmd/server"
)

// catalogPath returns the absolute path to standard_algorithms.json.
func catalogPath() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "..", "proto", "standard_algorithms.json")
}

// buildServer is a test helper that wires a fully functional Handler.
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

// seedPolicy creates a permissive policy via the policy engine in the
// testable handler's request scope.
func seedPolicy(t *testing.T, ctx context.Context, h *server.TestableHandler, name string, templates []string) string {
	t.Helper()

	type opRule struct {
		KeyOperations []string `json:"key_operations"`
	}
	rules := struct {
		Version           string   `json:"version"`
		AllowedTemplates  []string `json:"allowed_templates"`
		AllowedOperations *opRule  `json:"allowed_operations"`
	}{
		Version:          "1",
		AllowedTemplates: templates,
		AllowedOperations: &opRule{
			KeyOperations: []string{"create_key", "sign", "verify"},
		},
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

// TestSmoke_CreateKey_Sign_Verify exercises the full gRPC handler stack:
//
//	NewServer -> Handler.CreateKey -> Handler.Sign -> Handler.Verify
func TestSmoke_CreateKey_Sign_Verify(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)

	// TODO: change to CreatePolicy
	policyName := seedPolicy(t, ctx, h, "ecdsa-allow", []string{"ecdsa-p256-sha256-der"})

	// CreateKey
	createResp, err := h.Handler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:   "smoke-key",
		Policy: policyName,
		KeySpecification: &messagespb.CreateKeyRequest_TemplateId{
			TemplateId: "ecdsa-p256-sha256-der",
		},
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
	t.Logf("Created key: %s", keyName)

	// Sign
	payload := []byte("M1 smoke test payload - ECDSA-P256-SHA256")
	signResp, err := h.Handler.Sign(ctx, &messagespb.SignRequest{
		KeyName: keyName,
		Input:   payload,
		ScopeParams: &messagespb.SignRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signResp.GetSignature()) == 0 {
		t.Fatal("Sign returned empty signature")
	}
	t.Logf("Signature length: %d bytes", len(signResp.GetSignature()))

	// Verify (valid)
	verifyResp, err := h.Handler.Verify(ctx, &messagespb.VerifyRequest{
		KeyName:   keyName,
		Input:     payload,
		Signature: signResp.GetSignature(),
		Metadata:  signResp.GetMetadata(),
		ScopeParams: &messagespb.VerifyRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("Verify: expected valid=true for correct signature")
	}

	// Verify (tampered)
	tampered := make([]byte, len(payload))
	copy(tampered, payload)
	tampered[0] ^= 0xFF // flip first byte

	verifyBad, err := h.Handler.Verify(ctx, &messagespb.VerifyRequest{
		KeyName:   keyName,
		Input:     tampered,
		Signature: signResp.GetSignature(),
		Metadata:  signResp.GetMetadata(),
		ScopeParams: &messagespb.VerifyRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("Verify (tampered): %v", err)
	}
	if verifyBad.GetValid() {
		t.Error("Verify (tampered): expected valid=false for wrong payload")
	}

	t.Log("M1 smoke test PASSED")
}
