package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-core/errors"
)

// generateECDSAKey generates an ECDSA key pair for curve through libctx,
// returning SPKI-encoded public bytes and SEC1-encoded private bytes — the
// same encodings software.generateECDSAKey emits for the same curve, so
// material either provider generates parses under the other's parser
// (covered in ecdsa_test.go's cross-provider interop test, not assumed from
// the encoding labels matching).
func generateECDSAKey(ctx context.Context, libctx *ossl.Context, curve types.EllipticCurve) (pubDER, privDER []byte, _ error) {
	const op errors.Op = "openssl.generateECDSAKey"

	group, err := curveFor(ctx, op, curve)
	if err != nil {
		return nil, nil, err
	}

	key, err := libctx.GenerateKey(ossl.EC, ossl.WithGroup(group))
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	defer key.Close()

	pubDER, err = key.MarshalSPKI()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	privDER, err = key.MarshalSEC1()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	return pubDER, privDER, nil
}

// curveBits is the expected key size in bits for curve. ossl.Key has no
// Curve() accessor, so this is what checkCurveMatches's declared-vs-actual
// cross-check uses instead: Bits() is curve-specific for the three NIST
// prime curves this provider supports, so a mismatch here is the same
// signal software's checkCurveMatches catches by comparing curve names.
func curveBits(curve types.EllipticCurve) int {
	switch curve {
	case types.EllipticCurve_ELLIPTIC_CURVE_P256:
		return 256
	case types.EllipticCurve_ELLIPTIC_CURVE_P384:
		return 384
	case types.EllipticCurve_ELLIPTIC_CURVE_P521:
		return 521
	default:
		return 0
	}
}

// checkCurveMatches cross-checks a parsed key's actual type/size against
// the curve AlgorithmDetails declares -- catching the case where the
// declaration and the stored key have drifted apart, the same property
// software's checkCurveMatches guards.
func checkCurveMatches(ctx context.Context, op errors.Op, key *ossl.Key, declared types.EllipticCurve) error {
	wantBits := curveBits(declared)
	if key.Type() != ossl.EC || key.Bits() != wantBits {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"key type/size %s/%d does not match declared algorithm curve %s (want EC/%d)",
			key.Type(), key.Bits(), declared, wantBits)
	}
	return nil
}

// curveMinHash returns the minimum-strength hash EcdsaParams requires for
// curve, and the default applied when hash is left UNSPECIFIED -- mirrors
// software's curveMinHash exactly (P-256 min/default SHA-256, P-384
// min/default SHA-384, P-521 requires exactly SHA-512), so the same
// request behaves identically regardless of which provider serves it.
func curveMinHash(ctx context.Context, op errors.Op, curve types.EllipticCurve) (types.HashAlgorithm, error) {
	switch curve {
	case types.EllipticCurve_ELLIPTIC_CURVE_P256:
		return types.HashAlgorithm_HASH_ALGORITHM_SHA256, nil
	case types.EllipticCurve_ELLIPTIC_CURVE_P384:
		return types.HashAlgorithm_HASH_ALGORITHM_SHA384, nil
	case types.EllipticCurve_ELLIPTIC_CURVE_P521:
		return types.HashAlgorithm_HASH_ALGORITHM_SHA512, nil
	default:
		return 0, errors.New(ctx, op, errors.CodeNotImplemented, "unsupported ECDSA curve: %s", curve)
	}
}

// ecdsaDigestName resolves EcdsaParams.hash to the ossl.DigestName Key.Sign
// needs, applying the same default/minimum-strength contract software's
// ecdsaDigest applies -- relying on HashAlgorithm's numeric ordering
// (SHA-256=1 < SHA-384=2 < SHA-512=3) the same way software's own CEL rule
// does. Unlike software, there is no separate hashing step here: Key.Sign
// hashes payload internally under whatever digest this resolves to.
func ecdsaDigestName(ctx context.Context, op errors.Op, curve types.EllipticCurve, hash types.HashAlgorithm) (ossl.DigestName, error) {
	minHash, err := curveMinHash(ctx, op, curve)
	if err != nil {
		return "", err
	}

	resolvedHash := hash
	switch {
	case hash == types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED:
		resolvedHash = minHash
	case hash < minHash:
		return "", errors.New(ctx, op, errors.CodeInvalidArgument,
			"hash %s is below the minimum strength required for curve %s (minimum %s)", hash, curve, minHash)
	}
	return digestNameFor(ctx, op, resolvedHash)
}

// ecdsaSignatureFormat maps the typed SignatureFormat to ossl.SignatureFormat.
// UNSPECIFIED defaults to DER, matching EcdsaParams.signature_format's
// documented default and software's encodeECDSASignature.
func ecdsaSignatureFormat(ctx context.Context, op errors.Op, format types.SignatureFormat) (ossl.SignatureFormat, error) {
	switch format {
	case types.SignatureFormat_SIGNATURE_FORMAT_UNSPECIFIED, types.SignatureFormat_SIGNATURE_FORMAT_DER:
		return ossl.SignatureDER, nil
	case types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363:
		return ossl.SignatureP1363, nil
	default:
		// SIGNATURE_FORMAT_RAW is Ed25519/Ed448 native format -- ECDSA has
		// no equivalent distinct from P1363, so it is rejected here rather
		// than silently aliased to it, matching software's own rejection.
		return 0, errors.New(ctx, op, errors.CodeNotImplemented, "unsupported ECDSA signature format: %s", format)
	}
}

// ecdsaSignatureEncodingLabel maps the declared SignatureFormat to the
// artifact-encoding string recorded in ProviderOutput.encoding, matching
// software's ecdsaSignatureEncodingLabel exactly (same "der"/"p1363" labels).
func ecdsaSignatureEncodingLabel(format types.SignatureFormat) string {
	switch format {
	case types.SignatureFormat_SIGNATURE_FORMAT_IEEE_P1363:
		return "p1363"
	default:
		return "der"
	}
}

// signECDSA signs payload with the ECDSA private key in privDER.
//
// Unlike software, there is no manual ASN.1 (DER) or fixed-width (P1363)
// encoding step here: ossl-go's Key.Sign already produces the signature in
// the requested SignOptions.Format directly -- OpenSSL's own native DER, or
// ossl-go's built-in P1363 conversion (see ossl.SignatureFormat's doc
// comment: "OpenSSL only produces and consumes the DER form; the
// fixed-width form is converted here").
func signECDSA(ctx context.Context, libctx *ossl.Context, privDER, payload []byte, keyEncoding providerpb.PrivateKeyEncoding, curve types.EllipticCurve, hash types.HashAlgorithm, format types.SignatureFormat) ([]byte, error) {
	const op errors.Op = "openssl.signECDSA"

	key, err := parsePrivateKey(ctx, op, libctx, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	if err = checkCurveMatches(ctx, op, key, curve); err != nil {
		return nil, err
	}
	digest, err := ecdsaDigestName(ctx, op, curve, hash)
	if err != nil {
		return nil, err
	}
	sigFormat, err := ecdsaSignatureFormat(ctx, op, format)
	if err != nil {
		return nil, err
	}

	sig, err := key.Sign(payload, &ossl.SignOptions{Digest: digest, Format: sigFormat})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

// ecdsaDigestSignName resolves the DigestName SignDigest passes to ossl-go.
//
// Unlike Sign's ecdsaDigestName, this never applies curve-minimum-strength
// validation or defaulting from the curve — software's signECDSADigest takes
// no hash parameter at all, because Go's ecdsa.Sign treats its input as an
// opaque value to sign regardless of what produced it, with no length
// requirement. ossl-go's SignDigest is not that permissive: it always
// validates the digest length against a resolved digest name's size (see
// ossl.Key.SignDigest's doc comment), even for EC, where OpenSSL itself
// doesn't need to know the digest's origin either. An UNSPECIFIED
// hash_algorithm therefore still needs *some* digest name to satisfy that
// check, so it is inferred from the digest's own length here rather than
// rejected outright -- preserving software's permissiveness for the common
// case (a standard-length digest with no declared origin) while still
// giving ossl-go something concrete to validate against.
func ecdsaDigestSignName(ctx context.Context, op errors.Op, hash types.HashAlgorithm, digestLen int) (ossl.DigestName, error) {
	if hash != types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		return digestNameFor(ctx, op, hash)
	}
	switch digestLen {
	case 32:
		return ossl.SHA256, nil
	case 48:
		return ossl.SHA384, nil
	case 64:
		return ossl.SHA512, nil
	default:
		return "", errors.New(ctx, op, errors.CodeInvalidArgument,
			"cannot infer a hash algorithm for a %d-byte digest; declare hash_algorithm explicitly", digestLen)
	}
}

// signECDSADigest signs a pre-computed digest directly, without hashing.
// Used by SignDigest, where the caller has already computed the digest.
func signECDSADigest(ctx context.Context, libctx *ossl.Context, privDER, digest []byte, keyEncoding providerpb.PrivateKeyEncoding, curve types.EllipticCurve, hash types.HashAlgorithm, format types.SignatureFormat) ([]byte, error) {
	const op errors.Op = "openssl.signECDSADigest"

	key, err := parsePrivateKey(ctx, op, libctx, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	if err = checkCurveMatches(ctx, op, key, curve); err != nil {
		return nil, err
	}
	digestName, err := ecdsaDigestSignName(ctx, op, hash, len(digest))
	if err != nil {
		return nil, err
	}
	sigFormat, err := ecdsaSignatureFormat(ctx, op, format)
	if err != nil {
		return nil, err
	}

	sig, err := key.SignDigest(digest, &ossl.SignOptions{Digest: digestName, Format: sigFormat})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

// verifyECDSA verifies signature over payload with the ECDSA public key in
// pubDER. Key.Verify hashes payload internally under digest — same absence
// of a separate hashing step as signECDSA, and the same reason: malformed
// signature bytes and a genuinely wrong signature are both reported as
// ossl.ErrVerification (see verifyOutcome), never distinguished the way
// software's decodeECDSASignature does — ossl-go draws that line inside
// Key.Verify itself.
func verifyECDSA(ctx context.Context, libctx *ossl.Context, pubDER, payload, signature []byte, keyEncoding providerpb.PublicKeyEncoding, curve types.EllipticCurve, hash types.HashAlgorithm, format types.SignatureFormat) (bool, error) {
	const op errors.Op = "openssl.verifyECDSA"

	key, err := parsePublicKey(ctx, op, libctx, pubDER, keyEncoding)
	if err != nil {
		return false, err
	}
	defer key.Close()

	if err = checkCurveMatches(ctx, op, key, curve); err != nil {
		return false, err
	}
	digest, err := ecdsaDigestName(ctx, op, curve, hash)
	if err != nil {
		return false, err
	}
	sigFormat, err := ecdsaSignatureFormat(ctx, op, format)
	if err != nil {
		return false, err
	}

	return verifyOutcome(ctx, op, key.Verify(payload, signature, &ossl.SignOptions{Digest: digest, Format: sigFormat}))
}

// verifyECDSADigest verifies signature over a pre-computed digest directly,
// without hashing. Used by VerifyDigest, where the caller has already
// computed the digest. Shares ecdsaDigestSignName with signECDSADigest for
// the same reason: ossl-go's VerifyDigest validates digest length against a
// resolved digest name just as SignDigest does.
func verifyECDSADigest(ctx context.Context, libctx *ossl.Context, pubDER, digest, signature []byte, keyEncoding providerpb.PublicKeyEncoding, curve types.EllipticCurve, hash types.HashAlgorithm, format types.SignatureFormat) (bool, error) {
	const op errors.Op = "openssl.verifyECDSADigest"

	key, err := parsePublicKey(ctx, op, libctx, pubDER, keyEncoding)
	if err != nil {
		return false, err
	}
	defer key.Close()

	if err = checkCurveMatches(ctx, op, key, curve); err != nil {
		return false, err
	}
	digestName, err := ecdsaDigestSignName(ctx, op, hash, len(digest))
	if err != nil {
		return false, err
	}
	sigFormat, err := ecdsaSignatureFormat(ctx, op, format)
	if err != nil {
		return false, err
	}

	return verifyOutcome(ctx, op, key.VerifyDigest(digest, signature, &ossl.SignOptions{Digest: digestName, Format: sigFormat}))
}
