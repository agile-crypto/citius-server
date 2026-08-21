package openssl_test

import (
	"context"
	"testing"

	metapb "github.com/agile-crypto/citius-server/gen/go/api/messages"
	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

func TestEncryptDecrypt_AESCTR_roundTrip(t *testing.T) {
	for _, bits := range []uint32{128, 192, 256} {
		t.Run("", func(t *testing.T) {
			p, err := openssl.New(context.Background())
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			ctx := context.Background()
			keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCTRDetails(bits)})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			plaintext := []byte("AES-CTR round trip probe")
			encResp, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
				Algorithm:   aesCTRDetails(bits),
				KeyMaterial: keyResp.GetKeyMaterial(),
				Plaintext:   plaintext,
				ScopeParams: encryptRequestNoParams(),
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if len(encResp.GetCiphertext()) != len(plaintext) {
				t.Errorf("CTR is a stream cipher: ciphertext length %d should equal plaintext length %d",
					len(encResp.GetCiphertext()), len(plaintext))
			}

			decResp, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
				Algorithm:   aesCTRDetails(bits),
				KeyMaterial: keyResp.GetKeyMaterial(),
				Ciphertext:  encResp.GetCiphertext(),
				Output:      encResp.GetOutput(),
				ScopeParams: decryptRequestNoParams(),
			})
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(decResp.GetPlaintext()) != string(plaintext) {
				t.Errorf("round trip: got %q want %q", decResp.GetPlaintext(), plaintext)
			}
		})
	}
}

func TestEncrypt_AESCTR_noncesAreUnique(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCTRDetails(256)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	req := &providerpb.EncryptRequest{
		Algorithm:   aesCTRDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   []byte("same plaintext, twice"),
		ScopeParams: encryptRequestNoParams(),
	}
	r1, err := p.Encrypt(ctx, req)
	if err != nil {
		t.Fatalf("Encrypt (1st): %v", err)
	}
	r2, err := p.Encrypt(ctx, req)
	if err != nil {
		t.Fatalf("Encrypt (2nd): %v", err)
	}

	iv1, iv2 := r1.GetOutput().GetBlockCipherOutput().GetIv(), r2.GetOutput().GetBlockCipherOutput().GetIv()
	if string(iv1) == string(iv2) {
		t.Error("two nonces should not be identical")
	}
	// Same plaintext + different nonce must produce different ciphertext --
	// otherwise the "nonce" isn't actually varying the keystream.
	if string(r1.GetCiphertext()) == string(r2.GetCiphertext()) {
		t.Error("two ciphertexts under different nonces should not be identical")
	}
}

// TestDecrypt_AESCTR_wrongIV_producesDifferentPlaintext documents CTR's
// inherent lack of authentication: decrypting with the wrong IV does not
// error (there is no padding or tag to fail), it silently produces garbage
// -- matching software's identical documented behavior, not a gap unique
// to this implementation.
func TestDecrypt_AESCTR_wrongIV_producesDifferentPlaintext(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCTRDetails(256)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	plaintext := []byte("this plaintext will not survive a wrong IV")
	encResp, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesCTRDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: encryptRequestNoParams(),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wrongIV := append([]byte(nil), encResp.GetOutput().GetBlockCipherOutput().GetIv()...)
	wrongIV[0] ^= 0xff
	wrongOutput := &metapb.ProviderOutput{
		AlgorithmOutput: &metapb.ProviderOutput_BlockCipherOutput{
			BlockCipherOutput: &metapb.BlockCipherOutput{Iv: wrongIV},
		},
	}

	decResp, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   aesCTRDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Ciphertext:  encResp.GetCiphertext(),
		Output:      wrongOutput,
		ScopeParams: decryptRequestNoParams(),
	})
	if err != nil {
		t.Fatalf("Decrypt with wrong IV should not error (CTR has no authentication), got: %v", err)
	}
	if string(decResp.GetPlaintext()) == string(plaintext) {
		t.Error("decrypting with the wrong IV should not recover the original plaintext")
	}
}

func TestEncrypt_AESCTR_unsupportedNonceCounterSplit_returnsError(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCTRDetails(256)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	alg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesCtr{
			AesCtr: &types.AesCtrParams{KeySizeBits: 256, NonceSizeBits: 64, CounterBits: 64},
		},
	}
	_, err = p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   alg,
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   []byte("probe"),
		ScopeParams: encryptRequestNoParams(),
	})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for unsupported nonce/counter split, got: %v", err)
	}
}

// TestEncryptDecrypt_AESCTR_crossProviderInterop is the interop check the
// plan requires (I7): openssl encrypts, software decrypts, and vice versa.
func TestEncryptDecrypt_AESCTR_crossProviderInterop(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte("cross-provider AES-CTR interop probe")

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()
	sw := software.New()

	// Direction 1: openssl encrypts, software decrypts.
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCTRDetails(256)})
	if err != nil {
		t.Fatalf("openssl GenerateKey: %v", err)
	}
	osslEnc, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesCTRDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: encryptRequestNoParams(),
	})
	if err != nil {
		t.Fatalf("openssl Encrypt: %v", err)
	}
	swDec, err := sw.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   aesCTRDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Ciphertext:  osslEnc.GetCiphertext(),
		Output:      osslEnc.GetOutput(),
		ScopeParams: decryptRequestNoParams(),
	})
	if err != nil {
		t.Fatalf("software Decrypt of openssl-encrypted ciphertext: %v", err)
	}
	if string(swDec.GetPlaintext()) != string(plaintext) {
		t.Errorf("direction 1 round trip: got %q want %q", swDec.GetPlaintext(), plaintext)
	}

	// Direction 2: software encrypts, openssl decrypts.
	swKeyResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCTRDetails(256)})
	if err != nil {
		t.Fatalf("software GenerateKey: %v", err)
	}
	swEnc, err := sw.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesCTRDetails(256),
		KeyMaterial: swKeyResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: encryptRequestNoParams(),
	})
	if err != nil {
		t.Fatalf("software Encrypt: %v", err)
	}
	osslDec, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   aesCTRDetails(256),
		KeyMaterial: swKeyResp.GetKeyMaterial(),
		Ciphertext:  swEnc.GetCiphertext(),
		Output:      swEnc.GetOutput(),
		ScopeParams: decryptRequestNoParams(),
	})
	if err != nil {
		t.Fatalf("openssl Decrypt of software-encrypted ciphertext: %v", err)
	}
	if string(osslDec.GetPlaintext()) != string(plaintext) {
		t.Errorf("direction 2 round trip: got %q want %q", osslDec.GetPlaintext(), plaintext)
	}
}
