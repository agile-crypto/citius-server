package openssl_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

func encryptRequestAead(aad []byte) *providerpb.EncryptRequest_AeadParams {
	return &providerpb.EncryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{Aad: aad}}
}

func encryptRequestAeadForDecrypt(aad []byte) *providerpb.DecryptRequest_AeadParams {
	return &providerpb.DecryptRequest_AeadParams{AeadParams: &types.AeadEncryptParams{Aad: aad}}
}

// TestEncrypt_AESGCM_noncesAreUnique is the negative control proving
// encryptAESGCM generates a fresh random nonce per call rather than reusing
// one -- nonce reuse under AES-GCM breaks confidentiality and integrity
// both.
func TestEncrypt_AESGCM_noncesAreUnique(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesGCMDetails(256)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	enc1, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesGCMDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   []byte("message"),
		ScopeParams: encryptRequestAead(nil),
	})
	if err != nil {
		t.Fatalf("Encrypt (1st): %v", err)
	}
	enc2, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesGCMDetails(256),
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

// TestEncrypt_AESGCM_nonStandardIVAndTagTogether documents a genuine
// capability divergence from software: software's newAESGCM rejects
// declaring a non-standard IV size *and* a non-standard tag size at once,
// because Go's crypto/cipher only exposes NewGCMWithTagSize and
// NewGCMWithNonceSize as separate public constructors, never both together
// (see its doc comment). ossl-go's WithIVSize/WithTagSize set both
// independently through OpenSSL's OSSL_PARAM interface, with no such
// restriction -- verified empirically here, not assumed from parity with
// software. The round trip is checked directly against ossl-go's own Open,
// independent of this provider's Decrypt dispatch, since AEAD Decrypt is a
// later commit.
func TestEncrypt_AESGCM_nonStandardIVAndTagTogether(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	nonStandardDetails := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesGcm{
			AesGcm: &types.AesGcmParams{KeySizeBits: 256, IvSizeBits: 64, TagSizeBits: 96},
		},
	}
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: nonStandardDetails})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	plaintext := []byte("message")
	aad := []byte("aad")
	encResp, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   nonStandardDetails,
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: encryptRequestAead(aad),
	})
	if err != nil {
		t.Fatalf("Encrypt with a non-standard IV size (64 bits) and non-standard tag size (96 bits) together: %v", err)
	}

	nonce := encResp.GetOutput().GetAeadOutput().GetNonce()
	if got := len(nonce) * 8; got != 64 {
		t.Fatalf("nonce length: got %d bits want 64", got)
	}

	libctx, err := ossl.NewContext()
	if err != nil {
		t.Fatalf("ossl.NewContext: %v", err)
	}
	defer libctx.Close()
	aead, err := libctx.NewAEAD(ossl.AES256GCM, keyResp.GetKeyMaterial(), ossl.WithIVSize(8), ossl.WithTagSize(12))
	if err != nil {
		t.Fatalf("ossl-go NewAEAD: %v", err)
	}
	defer aead.Close()

	got, err := aead.Open(nil, nonce, encResp.GetCiphertext(), aad)
	if err != nil {
		t.Fatalf("ossl-go Open of openssl-encrypted ciphertext: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round trip: got %q want %q", got, plaintext)
	}
}

// TestEncrypt_AESGCM_keySizeMismatch_returnsError proves a key that does
// not actually match its declared size is rejected, not silently accepted
// under whatever size the byte count happens to imply. Unlike software,
// there is no citius-authored check here to negative-control: cipherNameFor
// resolves "AES-256-GCM" from the declared key_size_bits, and
// ctx.NewAEAD's own length check against that resolved name is what catches
// the mismatch (see encryptAESGCM's doc comment) -- this test verifies that
// behavior directly rather than assuming it.
func TestEncrypt_AESGCM_keySizeMismatch_returnsError(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	// A genuine 128-bit key, declared as AES-256-GCM.
	_, err = p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesGCMDetails(256),
		KeyMaterial: make([]byte, 16),
		Plaintext:   []byte("message"),
		ScopeParams: encryptRequestAead(nil),
	})
	if err == nil {
		t.Error("expected an error for a 16-byte key declared as AES-256-GCM (needs 32 bytes)")
	}
}

// TestEncryptDecrypt_AESGCM_crossProviderInterop completes the AEAD wire
// contract check: both directions (software & OpenSSL), proving the AeadOutput contract
// (nonce, tag length) is identical regardless of which provider produced
// it or which consumes it.
func TestEncryptDecrypt_AESGCM_crossProviderInterop(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte("cross-provider AES-GCM interop probe")
	aad := []byte("associated data")

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()
	sw := software.New()

	// Direction 1: openssl encrypts, software decrypts.
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesGCMDetails(256)})
	if err != nil {
		t.Fatalf("openssl GenerateKey: %v", err)
	}
	osslEnc, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesGCMDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: encryptRequestAead(aad),
	})
	if err != nil {
		t.Fatalf("openssl Encrypt: %v", err)
	}
	swDec, err := sw.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   aesGCMDetails(256),
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
	swKeyResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesGCMDetails(256)})
	if err != nil {
		t.Fatalf("software GenerateKey: %v", err)
	}
	swEnc, err := sw.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesGCMDetails(256),
		KeyMaterial: swKeyResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: encryptRequestAead(aad),
	})
	if err != nil {
		t.Fatalf("software Encrypt: %v", err)
	}
	osslDec, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   aesGCMDetails(256),
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

// TestDecrypt_AESGCM_tamperedCiphertext_returnsError is the negative
// control: a tampered ciphertext must fail authentication and surface as an
// error, not a panic and not silently-wrong plaintext.
func TestDecrypt_AESGCM_tamperedCiphertext_returnsError(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesGCMDetails(256)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	encResp, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesGCMDetails(256),
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
		Algorithm:   aesGCMDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Ciphertext:  tampered,
		Output:      encResp.GetOutput(),
		ScopeParams: encryptRequestAeadForDecrypt(nil),
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a tampered ciphertext, got: %v", err)
	}
}

// TestDecrypt_AESGCM_tamperedAAD_returnsError is the negative control
// proving AAD is genuinely authenticated, not merely accepted and ignored:
// decrypting with different AAD than was used at encryption time must fail.
func TestDecrypt_AESGCM_tamperedAAD_returnsError(t *testing.T) {
	ctx := context.Background()
	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesGCMDetails(256)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	encResp, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesGCMDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   []byte("message"),
		ScopeParams: encryptRequestAead([]byte("the original AAD")),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = p.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   aesGCMDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Ciphertext:  encResp.GetCiphertext(),
		Output:      encResp.GetOutput(),
		ScopeParams: encryptRequestAeadForDecrypt([]byte("a different AAD")),
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for mismatched AAD, got: %v", err)
	}
}
