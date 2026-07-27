package software_test

import (
	"context"
	"testing"

	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/provider"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

// These exercise the EXPLICIT branches directly (KeyOutput.encoding set to
// "sec1" or "pkcs8"), as opposed to the fallback branch that fires when it's
// unset — the other tests in this package (genECDSAKey, ecdsa_pkcs8_test.go)
// never set KeyOutput, so they only ever exercise the fallback.

func TestSign_ECDSA_explicitSEC1Encoding_succeeds(t *testing.T) {
	p, keyMaterial := genECDSAKey(t) // real key, SEC1-encoded (see provider.go)

	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("payload"),
		Algorithm:   ecdsaP256Details(),
		KeyOutput:   provider.NoOutput("sec1"),
	})
	if err != nil {
		t.Fatalf("Sign with explicit sec1 encoding: %v", err)
	}
}

func TestSign_ECDSA_explicitPKCS8Encoding_succeeds(t *testing.T) {
	pkcs8DER, _ := genECDSAPKCS8Key(t)

	_, err := software.New().Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: pkcs8DER,
		Input:       []byte("payload"),
		Algorithm:   ecdsaP256Details(),
		KeyOutput:   provider.NoOutput("pkcs8"),
	})
	if err != nil {
		t.Fatalf("Sign with explicit pkcs8 encoding: %v", err)
	}
}

// TestSign_ECDSA_explicitEncodingMismatch_returnsError proves an explicit
// encoding is trusted fully: it must NOT silently retry the other format
// when the declared encoding disagrees with the actual bytes — that would
// mask a real bug (stored encoding disagreeing with the stored key).
func TestSign_ECDSA_explicitEncodingMismatch_returnsError(t *testing.T) {
	p, keyMaterial := genECDSAKey(t) // real key, actually SEC1-encoded

	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("payload"),
		Algorithm:   ecdsaP256Details(),
		KeyOutput:   provider.NoOutput("pkcs8"), // wrong — bytes are SEC1
	})
	if err == nil {
		t.Fatal("expected error: declared pkcs8 but key material is sec1")
	}
}

func TestDigestSign_ECDSA_explicitSEC1Encoding_succeeds(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)

	_, err := p.DigestSign(context.Background(), &providerpb.DigestSignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Digest:      make([]byte, 32),
		Algorithm:   ecdsaP256Details(),
		KeyOutput:   provider.NoOutput("sec1"),
	})
	if err != nil {
		t.Fatalf("DigestSign with explicit sec1 encoding: %v", err)
	}
}

func TestDigestSign_ECDSA_explicitEncodingMismatch_returnsError(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)

	_, err := p.DigestSign(context.Background(), &providerpb.DigestSignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Digest:      make([]byte, 32),
		Algorithm:   ecdsaP256Details(),
		KeyOutput:   provider.NoOutput("pkcs8"), // wrong — bytes are sec1
	})
	if err == nil {
		t.Fatal("expected error: declared pkcs8 but key material is sec1")
	}
}
