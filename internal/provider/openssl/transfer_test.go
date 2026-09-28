package openssl_test

import (
	"context"
	"slices"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"

	"github.com/agile-crypto/citius-server/internal/provider/openssl"
)

// TestProvider_TransferCapabilities_matchGeneratedEncoding checks, for every
// algorithm family, that the stored-payload encoding advertised is the one
// GenerateKey emits: a core switching a key onto or off this provider acts
// on the advertisement.
func TestProvider_TransferCapabilities_matchGeneratedEncoding(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	algorithms := []struct {
		name string
		alg  *types.AlgorithmDetails
	}{
		{"ecdsa-p256", ecdsaP256Details()},
		{"rsa-pss", rsaPssDetails(2048)},
		{"rsa-pkcs1v15", rsaPkcs1v15Details(2048)},
		{"ed25519", ed25519Details()},
		{"ml-dsa-44", mlDSADetails(types.MlDsaParameterSet_ML_DSA_44)},
		{"aes-gcm", aesGCMDetails(256)},
		{"aes-cbc", &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_AesCbc{
			AesCbc: &types.AesCbcParams{KeySizeBits: 256, IvSizeBits: 128, Padding: types.PaddingScheme_PADDING_SCHEME_NONE},
		}}},
		{"aes-ctr", &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_AesCtr{
			AesCtr: &types.AesCtrParams{KeySizeBits: 256, NonceSizeBits: 64, CounterBits: 64},
		}}},
		{"chacha20-poly1305", &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_Chacha20Poly1305{
			Chacha20Poly1305: &types.ChaCha20Poly1305Params{NonceSizeBits: 96, BlockCounterBits: 32},
		}}},
	}
	for _, tt := range algorithms {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			want := []providerpb.PrivateKeyEncoding{resp.GetKeyMaterialEncoding()}
			got := provider.TransferOf(p, tt.alg)
			if !slices.Equal(got.Emit.StoredPayload, want) || !slices.Equal(got.Accept.StoredPayload, want) {
				t.Errorf("stored payload: emits %v, accepts %v; GenerateKey emitted %v",
					got.Emit.StoredPayload, got.Accept.StoredPayload, want)
			}
			if len(got.Emit.Plaintext)+len(got.Accept.Plaintext)+len(got.Emit.Wrapped)+len(got.Accept.Wrapped) > 0 {
				t.Errorf("advertises export, import or wrapping, which it does not implement: %+v", got)
			}
		})
	}

	if got := provider.TransferOf(p, &types.AlgorithmDetails{}); len(got.Emit.StoredPayload)+len(got.Accept.StoredPayload) > 0 {
		t.Errorf("advertises transfer for an algorithm it does not generate: %+v", got)
	}
}
