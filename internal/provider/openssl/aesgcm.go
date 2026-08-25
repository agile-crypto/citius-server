package openssl

import (
	"context"
	"crypto/rand"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	"github.com/agile-crypto/citius-server/internal/errors"
)

// encryptAESGCM encrypts plaintext under a freshly generated random nonce,
// returning the ciphertext (with the authentication tag appended, per the
// standard AEAD convention SealErr already follows) and the nonce the
// caller must record for decryption.
//
// Unlike encryptAESCBC/encryptAESCTR, there is no separate key-size check
// here: name is resolved from params.GetKeySizeBits() by the caller via
// cipherNameFor, and ctx.NewAEAD cross-checks the actual key material
// length against what that resolved cipher name requires internally (see
// ossl.Context.NewAEAD) — the same property "AES-256-GCM" as a name already
// gives it that "AES-256-GCM" as a bare aes.NewCipher call would not have,
// which is why software needs its own checkAESKeyMatchesDeclaredSize and
// this does not.
func encryptAESGCM(ctx context.Context, libctx *ossl.Context, name ossl.CipherName, keyMaterial, plaintext, aad []byte, params *types.AesGcmParams) (ciphertext, nonce []byte, _ error) {
	const op errors.Op = "openssl.encryptAESGCM"

	aead, err := libctx.NewAEAD(name, keyMaterial,
		ossl.WithIVSize(int(params.GetIvSizeBits()/8)), ossl.WithTagSize(int(params.GetTagSizeBits()/8)))
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	defer aead.Close()

	nonce = make([]byte, aead.NonceSize())
	if _, randErr := rand.Read(nonce); randErr != nil {
		return nil, nil, errors.Wrap(ctx, op, randErr)
	}

	ciphertext, err = aead.SealErr(nil, nonce, plaintext, aad)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	return ciphertext, nonce, nil
}
