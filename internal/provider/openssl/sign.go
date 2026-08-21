package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
)

// parsePrivateKey parses privDER as an asymmetric private key of the given
// encoding through libctx. Unlike software, this is one function for every
// algorithm rather than one per family: ossl-go's ParsePKCS8PrivateKey and
// ParseSEC1PrivateKey are generic, detecting the actual key type from the
// parsed structure rather than assuming one.
//
// Only the encodings this provider's own GenerateKey emits are handled —
// SEC1 (ECDSA) and PKCS8 (RSA, Ed25519, ML-DSA) — since nothing in this
// provider's own storage format needs anything else yet.
func parsePrivateKey(ctx context.Context, op errors.Op, libctx *ossl.Context, privDER []byte, encoding providerpb.PrivateKeyEncoding) (*ossl.Key, error) {
	switch encoding {
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1:
		key, err := libctx.ParseSEC1PrivateKey(privDER)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return key, nil
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8:
		key, err := libctx.ParsePKCS8PrivateKey(privDER)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return key, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			"unsupported private key encoding: %s", encoding)
	}
}
