package openssl

import (
	"context"
	"crypto/rand"
	stderrors "errors"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-server/internal/errors"
)

// checkAESCBCParamsValid rejects an ivSizeBits/padding combination this
// provider does not implement — the same restriction (128-bit IV, PKCS7
// padding only) software.checkAESCBCParamsValid applies. buf.validate does
// not enforce this cross-field relationship, and the "aes-*-cbc-pkcs7-128"
// catalog entries only ever cover this one combination, so anything else
// is rejected defensively rather than guessed at.
func checkAESCBCParamsValid(ctx context.Context, op errors.Op, ivSizeBits uint32, padding types.PaddingScheme) error {
	const aesCBCIVSizeBits = 128
	if ivSizeBits != aesCBCIVSizeBits {
		return errors.New(ctx, op, errors.CodeNotImplemented, "unsupported AES-CBC IV size: %d bits", ivSizeBits)
	}
	if padding != types.PaddingScheme_PADDING_SCHEME_PKCS7 {
		return errors.New(ctx, op, errors.CodeNotImplemented, "unsupported AES-CBC padding scheme: %s", padding)
	}
	return nil
}

// encryptAESCBC encrypts plaintext under a freshly generated random IV.
// name is resolved by the caller via cipherNameFor; padding is applied by
// ossl-go itself (PKCS#7, RFC 5652 §6.3) rather than hand-rolled the way
// software's pkcs7Pad does, since NewCipher already implements it.
func encryptAESCBC(ctx context.Context, libctx *ossl.Context, name ossl.CipherName, keyMaterial, plaintext []byte, params *types.AesCbcParams) (ciphertext, iv []byte, _ error) {
	const op errors.Op = "openssl.encryptAESCBC"

	if err := checkAESCBCParamsValid(ctx, op, params.GetIvSizeBits(), params.GetPadding()); err != nil {
		return nil, nil, err
	}

	cph, err := libctx.NewCipher(name, keyMaterial, ossl.WithPadding(ossl.PaddingPKCS7))
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	defer cph.Close()

	iv = make([]byte, cph.IVSize())
	if _, randErr := rand.Read(iv); randErr != nil {
		return nil, nil, errors.Wrap(ctx, op, randErr)
	}

	ciphertext, err = cph.Encrypt(nil, iv, plaintext)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	return ciphertext, iv, nil
}

// decryptAESCBC decrypts ciphertext using the IV recorded at encryption
// time. ossl.Cipher.Decrypt reports a padding failure as ossl.ErrVerification
// with no further detail (a deliberate padding-oracle defense — see its doc
// comment); this maps that to CodeInvalidArgument, the same code software's
// own pkcs7Unpad uses for the identical failure, since a bad IV/key/padding
// combination is a caller-input problem, not an internal one.
func decryptAESCBC(ctx context.Context, libctx *ossl.Context, name ossl.CipherName, keyMaterial, ciphertext, iv []byte, params *types.AesCbcParams) ([]byte, error) {
	const op errors.Op = "openssl.decryptAESCBC"

	if err := checkAESCBCParamsValid(ctx, op, params.GetIvSizeBits(), params.GetPadding()); err != nil {
		return nil, err
	}

	cph, err := libctx.NewCipher(name, keyMaterial, ossl.WithPadding(ossl.PaddingPKCS7))
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	defer cph.Close()

	plaintext, err := cph.Decrypt(nil, iv, ciphertext)
	if err != nil {
		if stderrors.Is(err, ossl.ErrVerification) {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "invalid PKCS#7 padding or wrong key/IV")
		}
		return nil, errors.Wrap(ctx, op, err)
	}
	return plaintext, nil
}
