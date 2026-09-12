package openssl_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

// TestEncryptDecrypt_ChaCha20Poly1305_crossProviderInterop mirrors
// TestEncryptDecrypt_AESGCM_crossProviderInterop.
func TestEncryptDecrypt_ChaCha20Poly1305_crossProviderInterop(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte("cross-provider ChaCha20-Poly1305 interop probe")
	aad := []byte("associated data")

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()
	sw := software.New()

	// Direction 1: openssl encrypts, software decrypts.
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: chacha20Poly1305Details()})
	if err != nil {
		t.Fatalf("openssl GenerateKey: %v", err)
	}
	osslEnc, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   chacha20Poly1305Details(),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: encryptRequestAead(aad),
	})
	if err != nil {
		t.Fatalf("openssl Encrypt: %v", err)
	}
	swDec, err := sw.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   chacha20Poly1305Details(),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Ciphertext:  osslEnc.GetCiphertext(),
		Output:      osslEnc.GetOutput(),
		ScopeParams: encryptRequestAeadForDecrypt(aad),
	})
	if err != nil {
		t.Fatalf("software Decrypt of openssl-encrypted ciphertext: %v", err)
	}
	if string(swDec.GetPlaintext()) != string(plaintext) {
		t.Errorf("direction 1 round trip: got %q want %q", swDec.GetPlaintext(), plaintext)
	}

	// Direction 2: software encrypts, openssl decrypts.
	swKeyResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: chacha20Poly1305Details()})
	if err != nil {
		t.Fatalf("software GenerateKey: %v", err)
	}
	swEnc, err := sw.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   chacha20Poly1305Details(),
		KeyMaterial: swKeyResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: encryptRequestAead(aad),
	})
	if err != nil {
		t.Fatalf("software Encrypt: %v", err)
	}
	osslDec, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   chacha20Poly1305Details(),
		KeyMaterial: swKeyResp.GetKeyMaterial(),
		Ciphertext:  swEnc.GetCiphertext(),
		Output:      swEnc.GetOutput(),
		ScopeParams: encryptRequestAeadForDecrypt(aad),
	})
	if err != nil {
		t.Fatalf("openssl Decrypt of software-encrypted ciphertext: %v", err)
	}
	if string(osslDec.GetPlaintext()) != string(plaintext) {
		t.Errorf("direction 2 round trip: got %q want %q", osslDec.GetPlaintext(), plaintext)
	}
}

// TestDecrypt_ChaCha20Poly1305_tamperedCiphertext_returnsError mirrors
// TestDecrypt_AESGCM_tamperedCiphertext_returnsError.
func TestDecrypt_ChaCha20Poly1305_tamperedCiphertext_returnsError(t *testing.T) {
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
	encResp, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   chacha20Poly1305Details(),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   []byte("tamper with this ciphertext after encryption"),
		ScopeParams: encryptRequestAead(nil),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := append([]byte(nil), encResp.GetCiphertext()...)
	tampered[0] ^= 0xff

	_, err = p.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   chacha20Poly1305Details(),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Ciphertext:  tampered,
		Output:      encResp.GetOutput(),
		ScopeParams: encryptRequestAeadForDecrypt(nil),
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a tampered ciphertext, got: %v", err)
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
