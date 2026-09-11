package openssl

import (
	"context"
	"crypto/rand"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
)

// checkAESCTRParamsValid rejects a nonce_size_bits/counter_bits split this
// provider does not implement — the same 96-bit-nonce/32-bit-counter-only
// restriction (NIST SP 800-38A, Appendix B.2) software.checkAESCTRParamsValid
// applies, and for the same reason: AesCtrParams' CEL rules constrain each
// field independently but not their sum, so nothing else rules out a split
// this provider has no counter-block construction for.
func checkAESCTRParamsValid(ctx context.Context, op errors.Op, nonceSizeBits, counterBits uint32) error {
	const (
		wantNonceSizeBits = 96
		wantCounterBits   = 32
	)
	if nonceSizeBits != wantNonceSizeBits || counterBits != wantCounterBits {
		return errors.New(ctx, op, errors.CodeNotImplemented,
			"unsupported AES-CTR nonce/counter split: %d/%d bits (only 96/32 is implemented)", nonceSizeBits, counterBits)
	}
	return nil
}

// encryptAESCTR encrypts plaintext under a freshly generated random nonce.
// name is resolved by the caller via cipherNameFor. Only the nonce portion
// of the 16-byte IV is randomized; the counter portion starts at zero — the
// same convention software's encryptAESCTR uses, and the only split
// ossl-go's CTR mode is asked to run under here.
func encryptAESCTR(ctx context.Context, libctx *ossl.Context, name ossl.CipherName, keyMaterial, plaintext []byte, params *types.AesCtrParams) (ciphertext, iv []byte, _ error) {
	const op errors.Op = "openssl.encryptAESCTR"

	if err := checkAESCTRParamsValid(ctx, op, params.GetNonceSizeBits(), params.GetCounterBits()); err != nil {
		return nil, nil, err
	}

	cph, err := libctx.NewCipher(name, keyMaterial)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	defer cph.Close()

	iv = make([]byte, cph.IVSize())
	nonceSizeBytes := params.GetNonceSizeBits() / 8
	if _, randErr := rand.Read(iv[:nonceSizeBytes]); randErr != nil {
		return nil, nil, errors.Wrap(ctx, op, randErr)
	}

	ciphertext, err = cph.Encrypt(nil, iv, plaintext)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	return ciphertext, iv, nil
}

// decryptAESCTR decrypts ciphertext using the counter block recorded at
// encryption time. CTR decrypt is the identical keystream-XOR operation as
// encrypt — there is no padding or authentication check, so unlike
// decryptAESCBC a wrong key or IV here does not surface as an error; it
// silently produces garbage plaintext. That is inherent to unauthenticated
// CTR mode, matching software's decryptAESCTR doc comment on the same point.
func decryptAESCTR(ctx context.Context, libctx *ossl.Context, name ossl.CipherName, keyMaterial, ciphertext, iv []byte, params *types.AesCtrParams) ([]byte, error) {
	const op errors.Op = "openssl.decryptAESCTR"

	if err := checkAESCTRParamsValid(ctx, op, params.GetNonceSizeBits(), params.GetCounterBits()); err != nil {
		return nil, err
	}

	cph, err := libctx.NewCipher(name, keyMaterial)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	defer cph.Close()

	plaintext, err := cph.Decrypt(nil, iv, ciphertext)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return plaintext, nil
}
