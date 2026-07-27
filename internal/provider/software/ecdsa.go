package software

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	"github.com/agile-crypto/citius-server/internal/errors"
)

// ECDSA private-key material encodings, recorded in
// GenerateKeyResponse.output.encoding at generation time and echoed back via
// SignRequest/DigestSignRequest.key_output.encoding so the parser doesn't
// have to guess.  Shared between generation (provider.go) and parsing
// (below) so both sides agree on the same string values.
const (
	encodingPKCS8 = "pkcs8"
	encodingSEC1  = "sec1"
)

// parseECDSAPrivateKey parses privDER as an ECDSA private key.
//
// When encoding is a recognized value, it selects the matching parser
// directly — GenerateKey already recorded which format was used, so there
// is nothing to guess.  A parse failure or a wrong key type under an
// explicit encoding is a real bug (stored encoding disagrees with the
// bytes) and is reported as such, not silently retried under the other
// format.
//
// When encoding is empty or unrecognized (e.g. a key created before this
// field existed), it falls back to trying PKCS#8 then SEC1.  This is safe
// specifically because key ENCODING is structurally self-describing
// (PKCS#8's PrivateKeyInfo wrapper vs SEC1's bare ECPrivateKey sequence
// parse cleanly as one or the other) — unlike signature SCHEME (PSS vs
// PKCS1v15), which cannot be inferred from key bytes alone and must always
// be dispatched from AlgorithmDetails.
func parseECDSAPrivateKey(ctx context.Context, op errors.Op, privDER []byte, encoding string) (*ecdsa.PrivateKey, error) {
	switch encoding {
	case encodingPKCS8:
		return parseECDSAPKCS8(ctx, op, privDER)
	case encodingSEC1:
		return parseECDSASEC1(ctx, op, privDER)
	default:
		// Unknown/empty encoding: distinguish "not PKCS#8 syntax" (worth
		// trying SEC1 next) from "valid PKCS#8, wrong key type" (decisive on
		// its own — SEC1 can only ever encode an EC key, so retrying it
		// would just produce a less informative parse error and mask the
		// real problem).  parseECDSAPKCS8 conflates the two into one error,
		// so that path is inlined here rather than reused.
		key, err := x509.ParsePKCS8PrivateKey(privDER)
		if err == nil {
			ecKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
					fmt.Sprintf("PKCS#8 key is not ECDSA: %T", key))
			}
			return ecKey, nil
		}
		return parseECDSASEC1(ctx, op, privDER)
	}
}

func parseECDSAPKCS8(ctx context.Context, op errors.Op, privDER []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("PKCS#8 key is not ECDSA: %T", key))
	}
	return ecKey, nil
}

func parseECDSASEC1(ctx context.Context, op errors.Op, privDER []byte) (*ecdsa.PrivateKey, error) {
	privKey, err := x509.ParseECPrivateKey(privDER)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return privKey, nil
}

// curveForAlgorithm maps the typed EllipticCurve enum to the stdlib curve
// implementation. Only the NIST prime curves are implemented here; secp256k1,
// the brainpool curves, and the binary K/B curves are valid per
// EcdsaParams.curve's proto constraint but have no support in this provider.
func curveForAlgorithm(ctx context.Context, op errors.Op, curve types.EllipticCurve) (elliptic.Curve, error) {
	switch curve {
	case types.EllipticCurve_ELLIPTIC_CURVE_P256:
		return elliptic.P256(), nil
	case types.EllipticCurve_ELLIPTIC_CURVE_P384:
		return elliptic.P384(), nil
	case types.EllipticCurve_ELLIPTIC_CURVE_P521:
		return elliptic.P521(), nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported ECDSA curve: %s", curve))
	}
}

// checkCurveMatches cross-checks a parsed key's actual curve against the
// curve AlgorithmDetails declares. AlgorithmDetails is authoritative for
// dispatch (hash selection, etc.) — this exists to catch the case where the
// declaration and the stored key have drifted apart, which would otherwise
// silently sign/verify against the wrong security level.
func checkCurveMatches(ctx context.Context, op errors.Op, keyCurve elliptic.Curve, declared types.EllipticCurve) error {
	wantCurve, err := curveForAlgorithm(ctx, op, declared)
	if err != nil {
		return err
	}
	if keyCurve.Params().Name != wantCurve.Params().Name {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("key curve %s does not match declared algorithm curve %s",
				keyCurve.Params().Name, wantCurve.Params().Name))
	}
	return nil
}

// curveMinHash returns the minimum-strength hash EcdsaParams requires for
// curve. The same value is also the default applied when EcdsaParams.hash is
// left UNSPECIFIED — see the ecdsa_curve_hash_match CEL rule in
// algorithm_params.proto: P-256 minimum/default SHA-256, P-384
// minimum/default SHA-384, P-521 requires exactly SHA-512.
func curveMinHash(ctx context.Context, op errors.Op, curve types.EllipticCurve) (types.HashAlgorithm, error) {
	switch curve {
	case types.EllipticCurve_ELLIPTIC_CURVE_P256:
		return types.HashAlgorithm_HASH_ALGORITHM_SHA256, nil
	case types.EllipticCurve_ELLIPTIC_CURVE_P384:
		return types.HashAlgorithm_HASH_ALGORITHM_SHA384, nil
	case types.EllipticCurve_ELLIPTIC_CURVE_P521:
		return types.HashAlgorithm_HASH_ALGORITHM_SHA512, nil
	default:
		return 0, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported ECDSA curve: %s", curve))
	}
}

// ecdsaDigest computes the hash-then-sign digest for payload under curve,
// applying EcdsaParams.hash's documented default/minimum-strength contract.
// hash < minHash relies on the HashAlgorithm enum's numeric ordering
// (SHA-256=1 < SHA-384=2 < SHA-512=3), the same ordering the proto's own CEL
// rule relies on ("Hash enum ordering: ... conveniently sortable").  Only
// SHA-256/384/512 are reachable past this check — the CEL rule permits no
// other hash for ECDSA.
func ecdsaDigest(ctx context.Context, op errors.Op, curve types.EllipticCurve, hash types.HashAlgorithm, payload []byte) ([]byte, error) {
	minHash, err := curveMinHash(ctx, op, curve)
	if err != nil {
		return nil, err
	}

	resolvedHash := hash
	switch {
	case hash == types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED:
		resolvedHash = minHash
	case hash < minHash:
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("hash %s is below the minimum strength required for curve %s (minimum %s)",
				hash, curve, minHash))
	}

	switch resolvedHash {
	case types.HashAlgorithm_HASH_ALGORITHM_SHA256:
		d := sha256.Sum256(payload)
		return d[:], nil
	case types.HashAlgorithm_HASH_ALGORITHM_SHA384:
		d := sha512.Sum384(payload)
		return d[:], nil
	case types.HashAlgorithm_HASH_ALGORITHM_SHA512:
		d := sha512.Sum512(payload)
		return d[:], nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported ECDSA hash algorithm: %s", resolvedHash))
	}
}

func generateECDSAKey(ctx context.Context, curve types.EllipticCurve) (pubDER, privDER []byte, _ error) {
	const op errors.Op = "software.generateECDSAKey"

	c, err := curveForAlgorithm(ctx, op, curve)
	if err != nil {
		return nil, nil, err
	}

	privKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	pubDER, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	privDER, err = x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	return pubDER, privDER, nil
}

func signECDSA(ctx context.Context, privDER, payload []byte, keyEncoding string, curve types.EllipticCurve, hash types.HashAlgorithm) ([]byte, error) {
	const op errors.Op = "software.signECDSA"

	privKey, err := parseECDSAPrivateKey(ctx, op, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	if err = checkCurveMatches(ctx, op, privKey.Curve, curve); err != nil {
		return nil, err
	}

	digest, err := ecdsaDigest(ctx, op, curve, hash, payload)
	if err != nil {
		return nil, err
	}

	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

// signECDSADigest signs a pre-computed digest directly, without hashing.
// Used by DigestSign where the caller has already computed the digest.
func signECDSADigest(ctx context.Context, privDER, digest []byte, keyEncoding string, curve types.EllipticCurve) ([]byte, error) {
	const op errors.Op = "software.signECDSADigest"

	privKey, err := parseECDSAPrivateKey(ctx, op, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	if err = checkCurveMatches(ctx, op, privKey.Curve, curve); err != nil {
		return nil, err
	}

	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

func verifyECDSA(ctx context.Context, pubDER, payload, signature []byte, curve types.EllipticCurve, hash types.HashAlgorithm) (bool, error) {
	const op errors.Op = "software.verifyECDSA"

	pubKeyAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false, errors.Wrap(ctx, op, err)
	}

	pubKey, ok := pubKeyAny.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New(ctx, op, errors.CodeInvalidArgument, "public key is not ECDSA")
	}
	if err = checkCurveMatches(ctx, op, pubKey.Curve, curve); err != nil {
		return false, err
	}

	digest, err := ecdsaDigest(ctx, op, curve, hash, payload)
	if err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(pubKey, digest, signature), nil
}

// verifyECDSADigest verifies a signature over a pre-computed digest directly,
// without hashing.  Used by DigestVerify.
func verifyECDSADigest(ctx context.Context, pubDER, digest, signature []byte, curve types.EllipticCurve) (bool, error) {
	const op errors.Op = "software.verifyECDSADigest"

	pubKeyAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false, errors.Wrap(ctx, op, err)
	}

	pubKey, ok := pubKeyAny.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New(ctx, op, errors.CodeInvalidArgument, "public key is not ECDSA")
	}
	if err = checkCurveMatches(ctx, op, pubKey.Curve, curve); err != nil {
		return false, err
	}

	return ecdsa.VerifyASN1(pubKey, digest, signature), nil
}
