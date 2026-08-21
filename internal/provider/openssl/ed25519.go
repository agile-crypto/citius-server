package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
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

// checkEd25519VariantSupported rejects Ed25519ctx, the one variant this
// provider has no catalog entry for (software does not support it either —
// see software's own SupportedAlgorithms doc comment). Pure and ph are both
// genuinely supported here through the same Sign call, unlike software,
// where ph requires the separate DigestSign entry point — see capability.go's
// "ed25519ph" entry, verified directly to work end-to-end.
func checkEd25519VariantSupported(ctx context.Context, op errors.Op, variant types.Ed25519Variant) error {
	switch variant {
	case types.Ed25519Variant_ED25519_VARIANT_UNSPECIFIED,
		types.Ed25519Variant_ED25519_VARIANT_PURE,
		types.Ed25519Variant_ED25519_VARIANT_PH:
		return nil
	default:
		return errors.New(ctx, op, errors.CodeNotImplemented, "unsupported Ed25519 variant: %s", variant)
	}
}

// signEd25519 signs payload with the Ed25519 private key in privDER. Pure
// and ph are both handled by this one Key.Sign call, distinguished only by
// SignOptions.Prehash — ph is prehashed by OpenSSL internally from the full
// message given here, not by the caller, so payload is identical either way.
//
// Context is deliberately never set on SignOptions: a non-nil Context (even
// zero-length) selects Ed25519ctx instead of pure Ed25519 for this specific
// key type (see ossl.SignOptions.Context's doc comment), and Ed25519ctx is
// rejected above, so this function must never construct one.
func signEd25519(ctx context.Context, libctx *ossl.Context, privDER, payload []byte, keyEncoding providerpb.PrivateKeyEncoding, variant types.Ed25519Variant) ([]byte, error) {
	const op errors.Op = "openssl.signEd25519"

	if err := checkEd25519VariantSupported(ctx, op, variant); err != nil {
		return nil, err
	}
	key, err := parsePrivateKey(ctx, op, libctx, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	if key.Type() != ossl.Ed25519 {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"key type %s does not match declared algorithm Ed25519", key.Type())
	}

	sig, err := key.Sign(payload, &ossl.SignOptions{Prehash: variant == types.Ed25519Variant_ED25519_VARIANT_PH})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}
