package openssl_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

func aesGCMDetails(keySizeBits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesGcm{
			AesGcm: &types.AesGcmParams{KeySizeBits: keySizeBits, IvSizeBits: 96, TagSizeBits: 128},
		},
	}
}

func aesCBCDetails(keySizeBits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesCbc{
			AesCbc: &types.AesCbcParams{KeySizeBits: keySizeBits, IvSizeBits: 128, Padding: types.PaddingScheme_PADDING_SCHEME_PKCS7},
		},
	}
}

func aesCTRDetails(keySizeBits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesCtr{
			AesCtr: &types.AesCtrParams{KeySizeBits: keySizeBits, NonceSizeBits: 96, CounterBits: 32},
		},
	}
}

func chacha20Poly1305Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Chacha20Poly1305{
			Chacha20Poly1305: &types.ChaCha20Poly1305Params{NonceSizeBits: 96, BlockCounterBits: 32},
		},
	}
}

func TestGenerateKey_symmetric_happyPath(t *testing.T) {
	tests := []struct {
		name     string
		alg      *types.AlgorithmDetails
		wantBits uint32
	}{
		{"aes-128-gcm", aesGCMDetails(128), 128},
		{"aes-192-gcm", aesGCMDetails(192), 192},
		{"aes-256-gcm", aesGCMDetails(256), 256},
		{"aes-128-cbc", aesCBCDetails(128), 128},
		{"aes-192-cbc", aesCBCDetails(192), 192},
		{"aes-256-cbc", aesCBCDetails(256), 256},
		{"aes-128-ctr", aesCTRDetails(128), 128},
		{"aes-192-ctr", aesCTRDetails(192), 192},
		{"aes-256-ctr", aesCTRDetails(256), 256},
		{"chacha20-poly1305", chacha20Poly1305Details(), 256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := openssl.New(context.Background())
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			wantBytes := int(tt.wantBits / 8)
			if got := len(resp.GetKeyMaterial()); got != wantBytes {
				t.Errorf("key material length: got %d bytes want %d", got, wantBytes)
			}
			if got := resp.GetKeyMaterialEncoding(); got != providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW {
				t.Errorf("KeyMaterialEncoding: got %v want RAW", got)
			}
			if len(resp.GetPublicKeyBytes()) != 0 {
				t.Errorf("expected no public key bytes for a symmetric key, got %d bytes", len(resp.GetPublicKeyBytes()))
			}
		})
	}
}

func TestGenerateKey_symmetric_keysAreUnique(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	r1, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesGCMDetails(256)})
	if err != nil {
		t.Fatalf("GenerateKey (1st): %v", err)
	}
	r2, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesGCMDetails(256)})
	if err != nil {
		t.Fatalf("GenerateKey (2nd): %v", err)
	}

	if string(r1.GetKeyMaterial()) == string(r2.GetKeyMaterial()) {
		t.Error("two generated keys should not be identical")
	}
}

// TestGenerateKey_AESGCM_unsupportedKeySize_returnsError mirrors software's
// test of the same name: a key size outside {128, 192, 256} is rejected.
// In this live path the rejection actually comes from validateRequest's
// buf.validate constraint (key_size_bits: {in: [128, 192, 256]}), which
// runs before checkAESKeySize is ever reached — the same layering software
// has, where checkAESKeySize is defense-in-depth for a caller that bypasses
// proto validation, not the layer this particular test exercises.
func TestGenerateKey_AESGCM_unsupportedKeySize_returnsError(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	_, err = p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: aesGCMDetails(100), // not one of 128/192/256
	})
	if err == nil {
		t.Fatal("expected error for unsupported AES key size")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

// TestGenerateKey_symmetric_crossProviderCompatible is the interop check
// the plan requires (I7), shaped differently than the asymmetric algorithms'
// versions: raw symmetric key bytes carry no format to parse, so there is
// no encoding mismatch to prove wrong. What is worth proving instead is
// that openssl-generated key bytes are directly usable by software's own,
// already-working AES-GCM Encrypt/Decrypt — a real round trip through a
// second implementation, not just "the byte length matches."
func TestGenerateKey_symmetric_crossProviderCompatible(t *testing.T) {
	ctx := context.Background()

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	genResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: aesGCMDetails(256)})
	if err != nil {
		t.Fatalf("openssl GenerateKey: %v", err)
	}

	sw := software.New()
	plaintext := []byte("cross-provider symmetric compatibility probe")
	encResp, err := sw.Encrypt(ctx, &providerpb.EncryptRequest{
		Algorithm:   aesGCMDetails(256),
		KeyMaterial: genResp.GetKeyMaterial(),
		Plaintext:   plaintext,
	})
	if err != nil {
		t.Fatalf("software.Encrypt using openssl-generated AES-256-GCM key: %v", err)
	}
	decResp, err := sw.Decrypt(ctx, &providerpb.DecryptRequest{
		Algorithm:   aesGCMDetails(256),
		KeyMaterial: genResp.GetKeyMaterial(),
		Ciphertext:  encResp.GetCiphertext(),
		Output:      encResp.GetOutput(),
	})
	if err != nil {
		t.Fatalf("software.Decrypt using openssl-generated AES-256-GCM key: %v", err)
	}
	if string(decResp.GetPlaintext()) != string(plaintext) {
		t.Errorf("round trip: got %q want %q", decResp.GetPlaintext(), plaintext)
	}
}
