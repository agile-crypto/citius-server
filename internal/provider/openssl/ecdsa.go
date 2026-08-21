package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
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
