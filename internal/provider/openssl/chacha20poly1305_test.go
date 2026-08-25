package openssl_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

// TestEncrypt_ChaCha20Poly1305_verifiesWithSoftware mirrors
// TestEncrypt_AESGCM_verifiesWithSoftware for ChaCha20-Poly1305.
func TestEncrypt_ChaCha20Poly1305_verifiesWithSoftware(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: chacha20Poly1305Details()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	plaintext := []byte("encrypt with openssl, decrypt with software")
	aad := []byte("associated data")
	encResp, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   chacha20Poly1305Details(),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: encryptRequestAead(aad),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	sw := software.New()
	decResp, err := sw.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   chacha20Poly1305Details(),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Ciphertext:  encResp.GetCiphertext(),
		Output:      encResp.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{Aad: aad}},
	})
	if err != nil {
		t.Fatalf("software Decrypt of openssl-encrypted ciphertext: %v", err)
	}
	if string(decResp.GetPlaintext()) != string(plaintext) {
		t.Errorf("round trip: got %q want %q", decResp.GetPlaintext(), plaintext)
	}
}

// TestEncrypt_ChaCha20Poly1305_noncesAreUnique mirrors
// TestEncrypt_AESGCM_noncesAreUnique.
func TestEncrypt_ChaCha20Poly1305_noncesAreUnique(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: chacha20Poly1305Details()})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	enc1, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   chacha20Poly1305Details(),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   []byte("message"),
		ScopeParams: encryptRequestAead(nil),
	})
	if err != nil {
		t.Fatalf("Encrypt (1st): %v", err)
	}
	enc2, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   chacha20Poly1305Details(),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   []byte("message"),
		ScopeParams: encryptRequestAead(nil),
	})
	if err != nil {
		t.Fatalf("Encrypt (2nd): %v", err)
	}

	nonce1 := enc1.GetOutput().GetAeadOutput().GetNonce()
	nonce2 := enc2.GetOutput().GetAeadOutput().GetNonce()
	if len(nonce1) == 0 {
		t.Fatal("expected non-empty nonce")
	}
	if string(nonce1) == string(nonce2) {
		t.Error("two encryptions under the same key produced the same nonce")
	}
}

// TestEncrypt_ChaCha20Poly1305_extendedNonceRejected is the negative
// control for cipherNameFor's XChaCha20-Poly1305 rejection: ossl-go has no
// cipher name for it (see cipherNameFor's doc comment), so a request for
// the extended-nonce variant must fail rather than silently fall back to
// the IETF variant's different nonce semantics.
func TestEncrypt_ChaCha20Poly1305_extendedNonceRejected(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	xchachaDetails := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Chacha20Poly1305{
			Chacha20Poly1305: &types.ChaCha20Poly1305Params{NonceSizeBits: 192, BlockCounterBits: 32, ExtendedNonce: true},
		},
	}
	_, err = p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   xchachaDetails,
		KeyMaterial: make([]byte, 32),
		Plaintext:   []byte("message"),
		ScopeParams: encryptRequestAead(nil),
	})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for XChaCha20-Poly1305, got: %v", err)
	}
}
