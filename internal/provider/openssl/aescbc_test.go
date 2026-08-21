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

func encryptRequestNoParams() *providerpb.EncryptRequest_NoParams {
	return &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}}
}

func decryptRequestNoParams() *providerpb.DecryptRequest_NoParams {
	return &providerpb.DecryptRequest_NoParams{NoParams: &types.NoParams{}}
}

func TestEncryptDecrypt_AESCBC_roundTrip(t *testing.T) {
	for _, bits := range []uint32{128, 192, 256} {
		t.Run("", func(t *testing.T) {
			p, err := openssl.New(context.Background())
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			ctx := context.Background()
			keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCBCDetails(bits)})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			plaintext := []byte("AES-CBC round trip probe, deliberately not block-aligned")
			encResp, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
				Algorithm:   aesCBCDetails(bits),
				KeyMaterial: keyResp.GetKeyMaterial(),
				Plaintext:   plaintext,
				ScopeParams: encryptRequestNoParams(),
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if len(encResp.GetOutput().GetBlockCipherOutput().GetIv()) != 16 {
				t.Fatalf("expected a 16-byte IV in Output, got %d bytes", len(encResp.GetOutput().GetBlockCipherOutput().GetIv()))
			}

			decResp, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
				Algorithm:   aesCBCDetails(bits),
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

func TestEncrypt_AESCBC_ivsAreUnique(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCBCDetails(256)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	req := &providerpb.EncryptRequest{
		Algorithm:   aesCBCDetails(256),
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
		t.Error("two IVs should not be identical")
	}
}

// TestDecrypt_AESCBC_tamperedCiphertext_returnsError is the negative
// control for decryptAESCBC's padding-failure handling: flipping a
// ciphertext byte must surface as an error, not silently decrypt into
// garbage, and specifically not panic.
func TestDecrypt_AESCBC_tamperedCiphertext_returnsError(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCBCDetails(256)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	encResp, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesCBCDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   []byte("tamper with this ciphertext after encryption"),
		ScopeParams: encryptRequestNoParams(),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a byte in the *last* block specifically: CBC decryption of any
	// other block recovers wrong plaintext there but leaves the final
	// block -- and therefore the PKCS#7 padding it carries -- untouched, so
	// decrypt would succeed anyway. Only corrupting the last block reliably
	// breaks the padding this test means to exercise.
	tampered := append([]byte(nil), encResp.GetCiphertext()...)
	tampered[len(tampered)-1] ^= 0xff

	_, err = p.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   aesCBCDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Ciphertext:  tampered,
		Output:      encResp.GetOutput(),
		ScopeParams: decryptRequestNoParams(),
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for tampered ciphertext, got: %v", err)
	}
}

func TestEncrypt_AESCBC_unsupportedPadding_returnsError(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCBCDetails(256)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	alg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesCbc{
			AesCbc: &types.AesCbcParams{KeySizeBits: 256, IvSizeBits: 128, Padding: types.PaddingScheme_PADDING_SCHEME_NONE},
		},
	}
	_, err = p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   alg,
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   []byte("0123456789abcdef"),
		ScopeParams: encryptRequestNoParams(),
	})
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for unsupported padding, got: %v", err)
	}
}

// TestEncryptDecrypt_AESCBC_crossProviderInterop is the interop check the
// plan requires (I7): openssl encrypts, software decrypts, and vice versa —
// a real round trip through a second implementation, not just a byte-shape
// comparison.
func TestEncryptDecrypt_AESCBC_crossProviderInterop(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte("cross-provider AES-CBC interop probe")

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()
	sw := software.New()

	// Direction 1: openssl encrypts, software decrypts.
	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCBCDetails(256)})
	if err != nil {
		t.Fatalf("openssl GenerateKey: %v", err)
	}
	osslEnc, err := p.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesCBCDetails(256),
		KeyMaterial: keyResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: encryptRequestNoParams(),
	})
	if err != nil {
		t.Fatalf("openssl Encrypt: %v", err)
	}
	swDec, err := sw.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   aesCBCDetails(256),
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
	swKeyResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesCBCDetails(256)})
	if err != nil {
		t.Fatalf("software GenerateKey: %v", err)
	}
	swEnc, err := sw.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesCBCDetails(256),
		KeyMaterial: swKeyResp.GetKeyMaterial(),
		Plaintext:   plaintext,
		ScopeParams: encryptRequestNoParams(),
	})
	if err != nil {
		t.Fatalf("software Encrypt: %v", err)
	}
	osslDec, err := p.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   aesCBCDetails(256),
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
