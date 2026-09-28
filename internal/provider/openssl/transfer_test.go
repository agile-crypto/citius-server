package openssl_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"reflect"
	"slices"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"

	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

// TestProvider_TransferCapabilities_matchGeneratedEncoding checks, for every
// algorithm family, that the stored-payload encoding advertised is the one
// GenerateKey emits, that the key material really is in it, and that the
// software provider advertises the same: a core switching a key onto or off
// this provider acts on the advertisement.
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
			requireEncodedAs(t, resp.GetKeyMaterialEncoding(), resp.GetKeyMaterial())
			want := []providerpb.PrivateKeyEncoding{resp.GetKeyMaterialEncoding()}
			got := provider.TransferOf(p, tt.alg)
			if !slices.Equal(got.Emit.StoredPayload, want) || !slices.Equal(got.Accept.StoredPayload, want) {
				t.Errorf("stored payload: emits %v, accepts %v; GenerateKey emitted %v",
					got.Emit.StoredPayload, got.Accept.StoredPayload, want)
			}
			// PROVIDER_SWITCH between the two in-process providers relies on
			// their advertising the same channel.
			if sw := provider.TransferOf(software.New(), tt.alg); !reflect.DeepEqual(sw, got) {
				t.Errorf("software advertises %+v, openssl %+v", sw, got)
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

// pkcs8 is the outer structure of a PKCS#8 PrivateKeyInfo (RFC 5208), enough
// to tell PKCS#8 from other encodings for any key type.
type pkcs8 struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// requireEncodedAs fails unless key parses in encoding.
func requireEncodedAs(t *testing.T, encoding providerpb.PrivateKeyEncoding, key []byte) {
	t.Helper()
	var err error
	switch encoding {
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1:
		_, err = x509.ParseECPrivateKey(key)
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8:
		var info pkcs8
		var rest []byte
		if rest, err = asn1.Unmarshal(key, &info); err == nil && len(rest) > 0 {
			err = fmt.Errorf("%d trailing bytes", len(rest))
		}
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW:
		if n := len(key); n != 16 && n != 24 && n != 32 {
			err = fmt.Errorf("%d bytes is no symmetric key size", n)
		}
	default:
		err = fmt.Errorf("unexpected encoding %s", encoding)
	}
	if err != nil {
		t.Errorf("key material is not %s: %v", encoding, err)
	}
}
