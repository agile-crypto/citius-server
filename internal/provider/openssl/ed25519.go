package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

	"github.com/agile-crypto/citius-server/internal/errors"
)

// generateEd25519Key generates an Ed25519 key pair through libctx,
// returning PKCS#8-encoded private bytes and SPKI-encoded public bytes —
// the same encodings software.generateEd25519Key emits, so material either
// provider generates parses under the other's parser.
//
// The variant (pure, ctx, ph) is not part of the key at all — it is a
// SignOptions choice made at Sign() time, same as software's approach — so
// generation is identical regardless of which template (ed25519,
// ed25519ph) requested it, and this function takes no variant parameter.
func generateEd25519Key(ctx context.Context, libctx *ossl.Context) (pubDER, privDER []byte, _ error) {
	const op errors.Op = "openssl.generateEd25519Key"

	key, err := libctx.GenerateKey(ossl.Ed25519)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	defer key.Close()

	pubDER, err = key.MarshalSPKI()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	privDER, err = key.MarshalPKCS8()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	return pubDER, privDER, nil
}
