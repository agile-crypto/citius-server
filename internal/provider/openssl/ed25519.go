package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-core/errors"
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
// where ph requires the separate SignDigest entry point — see capability.go's
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

// checkEd25519PHHash validates that a SignDigest call declares SHA-512 as
// the digest's origin hash. Unlike RSA's prehashed variants, Ed25519ph is
// not generic over hash algorithm — RFC 8032 §5.1 defines PH(x) = SHA-512(x),
// full stop, so there is no "Ed25519ph with SHA-384" or similar.
// validateDigestLength alone cannot catch a wrong hash here: SHA3-512,
// BLAKE2b-512, and others also produce 64-byte digests, so a caller
// declaring one of those would otherwise slip through unnoticed. Mirrors
// software's checkEd25519PHHash exactly.
func checkEd25519PHHash(ctx context.Context, op errors.Op, hashAlg types.HashAlgorithm) error {
	switch hashAlg {
	case types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, types.HashAlgorithm_HASH_ALGORITHM_SHA512:
		return nil
	default:
		return errors.New(ctx, op, errors.CodeNotImplemented,
			"Ed25519ph requires a SHA-512 digest, got hash_algorithm=%s", hashAlg)
	}
}

// signEd25519PHDigest signs a pre-computed SHA-512 digest with Ed25519ph
// (RFC 8032). Used by SignDigest, where the caller has already hashed the
// message with SHA-512 — the mandatory hash for this variant.
//
// This is the one algorithm where SignDigest genuinely needs the raw
// EVP_PKEY_sign entry point Key.SignDigest provides: Key.Sign's Prehash
// option always hashes whatever it is given, so passing an
// already-computed digest through it would hash it a second time and sign
// SHA-512(digest) instead of SHA-512(message) -- see ossl.Key.SignDigest's
// doc comment.
func signEd25519PHDigest(ctx context.Context, libctx *ossl.Context, privDER, digest []byte, keyEncoding providerpb.PrivateKeyEncoding, hashAlg types.HashAlgorithm) ([]byte, error) {
	const op errors.Op = "openssl.signEd25519PHDigest"

	if err := checkEd25519PHHash(ctx, op, hashAlg); err != nil {
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

	sig, err := key.SignDigest(digest, &ossl.SignOptions{Prehash: true})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

// verifyEd25519 verifies signature over payload with the Ed25519 public key
// in pubDER. Pure and ph are both handled by this one Key.Verify call, the
// same symmetry signEd25519 has on the sign side -- unlike software, whose
// regular Verify only reaches pure Ed25519 (ph requires the separate
// VerifyDigest entry point there).
func verifyEd25519(ctx context.Context, libctx *ossl.Context, pubDER, payload, signature []byte, keyEncoding providerpb.PublicKeyEncoding, variant types.Ed25519Variant) (bool, error) {
	const op errors.Op = "openssl.verifyEd25519"

	if err := checkEd25519VariantSupported(ctx, op, variant); err != nil {
		return false, err
	}
	key, err := parsePublicKey(ctx, op, libctx, pubDER, keyEncoding)
	if err != nil {
		return false, err
	}
	defer key.Close()

	if key.Type() != ossl.Ed25519 {
		return false, errors.New(ctx, op, errors.CodeInvalidArgument,
			"key type %s does not match declared algorithm Ed25519", key.Type())
	}

	return verifyOutcome(ctx, op, key.Verify(payload, signature, &ossl.SignOptions{Prehash: variant == types.Ed25519Variant_ED25519_VARIANT_PH}))
}

// verifyEd25519PHDigest verifies a signature over a pre-computed SHA-512
// digest with Ed25519ph (RFC 8032). Used by VerifyDigest, mirroring
// signEd25519PHDigest: Key.VerifyDigest is the raw EVP_PKEY_verify entry
// point this needs for the same reason Key.SignDigest is on the sign side.
func verifyEd25519PHDigest(ctx context.Context, libctx *ossl.Context, pubDER, digest, signature []byte, keyEncoding providerpb.PublicKeyEncoding, hashAlg types.HashAlgorithm) (bool, error) {
	const op errors.Op = "openssl.verifyEd25519PHDigest"

	if err := checkEd25519PHHash(ctx, op, hashAlg); err != nil {
		return false, err
	}
	key, err := parsePublicKey(ctx, op, libctx, pubDER, keyEncoding)
	if err != nil {
		return false, err
	}
	defer key.Close()

	if key.Type() != ossl.Ed25519 {
		return false, errors.New(ctx, op, errors.CodeInvalidArgument,
			"key type %s does not match declared algorithm Ed25519", key.Type())
	}

	return verifyOutcome(ctx, op, key.VerifyDigest(digest, signature, &ossl.SignOptions{Prehash: true}))
}
