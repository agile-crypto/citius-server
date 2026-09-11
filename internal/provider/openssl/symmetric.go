package openssl

import (
	"context"
	"crypto/rand"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
)

// generateSymmetricKey dispatches AES-GCM/CBC/CTR and ChaCha20-Poly1305 key
// generation. Key generation is identical across all three AES modes and
// needs no mode-specific branching of its own — the same shape
// software.generateSymmetricKey uses, and not by coincidence: raw symmetric
// key material has no OpenSSL-specific behavior to route through (ossl-go
// exposes no random-bytes API of its own), so this file uses crypto/rand
// exactly like software does, making the two providers' symmetric key
// material byte-for-byte interchangeable by construction.
func generateSymmetricKey(ctx context.Context, algorithm *types.AlgorithmDetails) ([]byte, error) {
	const op errors.Op = "openssl.generateSymmetricKey"

	switch alg := algorithm.GetAlgorithm().(type) {
	case *types.AlgorithmDetails_AesGcm:
		return generateAESKey(ctx, alg.AesGcm.GetKeySizeBits())
	case *types.AlgorithmDetails_AesCbc:
		return generateAESKey(ctx, alg.AesCbc.GetKeySizeBits())
	case *types.AlgorithmDetails_AesCtr:
		return generateAESKey(ctx, alg.AesCtr.GetKeySizeBits())
	case *types.AlgorithmDetails_Chacha20Poly1305:
		return generateChaCha20Key(ctx)
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			"unsupported symmetric algorithm type: %T", algorithm.GetAlgorithm())
	}
}

// checkAESKeySize rejects any AES key size outside the three FIPS-197
// options, since buf.validate does not run at this in-process layer.
func checkAESKeySize(ctx context.Context, op errors.Op, keySizeBits uint32) error {
	switch keySizeBits {
	case 128, 192, 256:
		return nil
	default:
		return errors.New(ctx, op, errors.CodeNotImplemented, "unsupported AES key size: %d bits", keySizeBits)
	}
}

// generateAESKey generates raw AES key material. Key generation is
// identical across AES-GCM/CBC/CTR — the mode only affects how the key is
// later used, not how it is produced — so this one function backs all
// three AlgorithmDetails arms. No ossl.Key is created here, so there is
// nothing to Close: raw symmetric bytes carry no OpenSSL object at
// generation time — ossl.NewAEAD/NewCipher build their own handle from
// these bytes only when the key is actually used, in Encrypt/Decrypt.
func generateAESKey(ctx context.Context, keySizeBits uint32) ([]byte, error) {
	const op errors.Op = "openssl.generateAESKey"

	if err := checkAESKeySize(ctx, op, keySizeBits); err != nil {
		return nil, err
	}
	key := make([]byte, keySizeBits/8)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return key, nil
}

// generateChaCha20Key generates raw ChaCha20 key material. Unlike AES,
// ChaCha20Poly1305Params carries no key_size_bits field at all — RFC 8439
// fixes the key at 256 bits regardless of the IETF/XChaCha20 nonce variant
// in use, so there is no caller-configurable size to validate.
func generateChaCha20Key(ctx context.Context) ([]byte, error) {
	const op errors.Op = "openssl.generateChaCha20Key"

	const chacha20KeySizeBytes = 32
	key := make([]byte, chacha20KeySizeBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return key, nil
}
