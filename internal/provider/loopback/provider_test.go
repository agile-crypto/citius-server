package loopback_test

import (
	"bytes"
	"context"
	"testing"

	types "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/provider/loopback"
)

// ecdsaP256Details returns an AlgorithmDetails for ECDSA-P256-SHA256.
func ecdsaP256Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{
				Curve: types.EllipticCurve_ELLIPTIC_CURVE_P256,
				Hash:  types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			},
		},
	}
}

// Compile-time assertions
var (
	_ provider.Backend                     = (*loopback.Provider)(nil)
	_ provider.AlgorithmCapabilityProvider = (*loopback.Provider)(nil)
)

func TestProvider_Name(t *testing.T) {
	p := loopback.New()
	if got := p.Name(); got != "loopback" {
		t.Errorf("Name: got %q want %q", got, "loopback")
	}
}

func TestProvider_Type(t *testing.T) {
	p := loopback.New()
	if got := p.Type(); got != "loopback" {
		t.Errorf("Type: got %q want %q", got, "loopback")
	}
}

func TestProvider_SupportedAlgorithms_returnsBothM1Algorithms(t *testing.T) {
	p := loopback.New()
	algs := p.SupportedAlgorithms()
	if len(algs) == 0 {
		t.Fatal("expected at least one supported algorithm")
	}
	ids := make(map[string]bool)
	for _, id := range algs {
		ids[id] = true
	}
	for _, want := range []string{"ecdsa-p256-sha256", "ml-dsa-65"} {
		if !ids[want] {
			t.Errorf("missing algorithm %q", want)
		}
	}
}

func TestProvider_GenerateKey_returnsSyntheticBytes(t *testing.T) {
	p := loopback.New()
	req := provider.GenerateKeyRequest{Algorithm: ecdsaP256Details()}
	result, err := p.GenerateKey(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(result.PublicKeyBytes) == 0 {
		t.Error("expected non-empty public key bytes")
	}
	if len(result.PrivateKeyBytes) == 0 {
		t.Error("expected non-empty private key bytes")
	}
}

func TestProvider_Sign_echoesInput(t *testing.T) {
	p := loopback.New()
	payload := []byte("hello world")
	req := provider.SignRequest{
		Input: payload,
	}
	result, err := p.Sign(context.Background(), req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(result.Signature, payload) {
		t.Errorf("Sign: signature should equal payload for loopback provider")
	}
}

func TestProvider_Verify_matchingInputAndSignature_returnsTrue(t *testing.T) {
	p := loopback.New()
	payload := []byte("test message")
	req := provider.VerifyRequest{
		Input:     payload,
		Signature: payload, // loopback: sig == input
	}
	result, err := p.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Valid {
		t.Error("Verify: expected valid=true when signature == input")
	}
}

func TestProvider_Verify_mismatchedSignature_returnsFalse(t *testing.T) {
	p := loopback.New()
	req := provider.VerifyRequest{
		Input:     []byte("original"),
		Signature: []byte("tampered"),
	}
	result, err := p.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Valid {
		t.Error("Verify: expected valid=false for mismatched signature")
	}
}

func TestProvider_Verify_emptySignature_returnsFalse(t *testing.T) {
	p := loopback.New()
	req := provider.VerifyRequest{
		Input:     []byte("data"),
		Signature: nil,
	}
	result, err := p.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Valid {
		t.Error("Verify: expected valid=false for nil signature")
	}
}

func TestProvider_SignThenVerify_roundtrip(t *testing.T) {
	p := loopback.New()
	ctx := context.Background()
	payload := []byte("round-trip test")

	signResult, err := p.Sign(ctx, provider.SignRequest{
		Input: payload,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyResult, err := p.Verify(ctx, provider.VerifyRequest{
		Input:     payload,
		Signature: signResult.Signature,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResult.Valid {
		t.Error("round-trip: Sign then Verify should return valid=true")
	}
}

func TestProvider_DestroyKey_succeeds(t *testing.T) {
	p := loopback.New()
	err := p.DestroyKey(context.Background(), "any-key-id")
	if err != nil {
		t.Errorf("DestroyKey: unexpected error %v", err)
	}
}

func TestProvider_ExportPublicKey_returnsDeterministicBytes(t *testing.T) {
	p := loopback.New()
	keyID := "test-key-123"
	pubKey, err := p.ExportPublicKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("ExportPublicKey: %v", err)
	}
	if len(pubKey) == 0 {
		t.Error("expected non-empty public key bytes")
	}
	// Should be deterministic for the same keyID
	pubKey2, _ := p.ExportPublicKey(context.Background(), keyID)
	if !bytes.Equal(pubKey, pubKey2) {
		t.Error("ExportPublicKey should be deterministic for same keyID")
	}
}
