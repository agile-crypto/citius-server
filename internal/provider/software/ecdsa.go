package software

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

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

func generateECDSAP256Key(ctx context.Context) (pubDER, privDER []byte, _ error) {
	const op errors.Op = "software.generateECDSAP256Key"

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

func signECDSAP256(ctx context.Context, privDER, payload []byte, keyEncoding string) ([]byte, error) {
	const op errors.Op = "software.signECDSAP256"

	privKey, err := parseECDSAPrivateKey(ctx, op, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:])
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	return sig, nil
}

// signECDSAP256Digest signs a pre-computed digest directly, without hashing.
// Used by DigestSign where the caller has already computed the digest.
func signECDSAP256Digest(ctx context.Context, privDER, digest []byte, keyEncoding string) ([]byte, error) {
	const op errors.Op = "software.signECDSAP256Digest"

	privKey, err := parseECDSAPrivateKey(ctx, op, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}

	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	return sig, nil
}

func verifyECDSAP256(ctx context.Context, pubDER, payload, signature []byte) (bool, error) {
	const op errors.Op = "software.verifyECDSAP256"

	pubKeyAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false, errors.Wrap(ctx, op, err)
	}

	pubKey, ok := pubKeyAny.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New(ctx, op, errors.CodeInvalidArgument, "public key is not ECDSA")
	}

	digest := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(pubKey, digest[:], signature), nil
}

// verifyECDSAP256Digest verifies a signature over a pre-computed digest directly,
// without hashing.  Used by DigestVerify.
func verifyECDSAP256Digest(ctx context.Context, pubDER, digest, signature []byte) (bool, error) {
	const op errors.Op = "software.verifyECDSAP256Digest"

	pubKeyAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false, errors.Wrap(ctx, op, err)
	}

	pubKey, ok := pubKeyAny.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New(ctx, op, errors.CodeInvalidArgument, "public key is not ECDSA")
	}

	return ecdsa.VerifyASN1(pubKey, digest, signature), nil
}
