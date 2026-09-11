package openssl

import (
	"context"
	"crypto/rand"

	"github.com/agile-crypto/ossl-go/ossl"

	"github.com/agile-crypto/citius-core/errors"
)

// chaCha20Poly1305TagSizeBytes is the fixed Poly1305 authentication tag
// length (128 bits) for the one variant this provider supports — matches
// software.ChaCha20Poly1305TagSizeBytes, since RFC 8439 fixes this
// regardless of which provider computes it.
const chaCha20Poly1305TagSizeBytes = 16

// encryptChaCha20Poly1305 mirrors encryptAESGCM. Unlike AES-GCM, there is no
// IV/tag size to negotiate: the only variant cipherNameFor's caller resolves
// ossl.ChaCha20Poly1305 for is the RFC 8439 IETF form (96-bit nonce, 32-bit
// counter, non-extended) — XChaCha20-Poly1305 is rejected before this
// function is ever called (see cipherNameFor's doc comment) — so
// ctx.NewAEAD's defaults (12-byte nonce, 16-byte tag) are exactly right
// with no WithIVSize/WithTagSize override.
func encryptChaCha20Poly1305(ctx context.Context, libctx *ossl.Context, keyMaterial, plaintext, aad []byte) (ciphertext, nonce []byte, _ error) {
	const op errors.Op = "openssl.encryptChaCha20Poly1305"

	aead, err := libctx.NewAEAD(ossl.ChaCha20Poly1305, keyMaterial)
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

// decryptChaCha20Poly1305 mirrors decryptAESGCM, including collapsing every
// failure mode (tampered ciphertext, wrong tag, wrong AAD, wrong key) into
// one generic authentication error — the same convention
// software.decryptChaCha20Poly1305 documents.
func decryptChaCha20Poly1305(ctx context.Context, libctx *ossl.Context, keyMaterial, ciphertext, nonce, aad []byte) ([]byte, error) {
	const op errors.Op = "openssl.decryptChaCha20Poly1305"

	aead, err := libctx.NewAEAD(ossl.ChaCha20Poly1305, keyMaterial)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	defer aead.Close()

	if len(nonce) != aead.NonceSize() {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"nonce is %d bytes, want %d bytes", len(nonce), aead.NonceSize())
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "ChaCha20-Poly1305 authentication failed")
	}
	return plaintext, nil
}
