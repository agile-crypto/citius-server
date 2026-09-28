package openssl

import (
	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
)

// privateKeyEncoding returns the encoding of the private key GenerateKey
// emits for alg, or UNSPECIFIED for an algorithm this provider does not
// generate: SEC1 (RFC 5915) for ECDSA, PKCS#8 for RSA, Ed25519 and ML-DSA
// (wrapping the seed), and the raw key bytes for symmetric algorithms.
func privateKeyEncoding(alg *types.AlgorithmDetails) providerpb.PrivateKeyEncoding {
	switch alg.GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		return providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1
	case *types.AlgorithmDetails_MlDsa, *types.AlgorithmDetails_RsaPss, *types.AlgorithmDetails_RsaPkcs1V15,
		*types.AlgorithmDetails_Ed25519:
		return providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8
	case *types.AlgorithmDetails_AesGcm, *types.AlgorithmDetails_AesCbc, *types.AlgorithmDetails_AesCtr,
		*types.AlgorithmDetails_Chacha20Poly1305:
		return providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW
	default:
		return providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_UNSPECIFIED
	}
}

// TransferCapabilities advertises the stored-payload channel for alg: the
// stored payload is the self-contained key bytes GenerateKey emits, which
// this provider can release to another provider, and it accepts another
// provider's payload in the same encoding. It exports, imports and wraps no
// key.
func (p *Provider) TransferCapabilities(alg *types.AlgorithmDetails) provider.Transfer {
	encoding := privateKeyEncoding(alg)
	if encoding == providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_UNSPECIFIED {
		return provider.Transfer{}
	}
	stored := provider.Channels{StoredPayload: []providerpb.PrivateKeyEncoding{encoding}}
	return provider.Transfer{Emit: stored, Accept: stored}
}

// Compile-time assertion: Provider implements TransferDescriber.
var _ provider.TransferDescriber = (*Provider)(nil)
