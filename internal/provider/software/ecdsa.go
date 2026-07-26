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

// parseECDSAPrivateKey parses privDER as an ECDSA private key, accepting
// either PKCS#8 (RFC 5958) or the legacy SEC1 (RFC 5915) encoding that
// generateECDSAP256Key currently produces.
//
// PKCS#8 is tried first — it's the self-describing, standard encoding used
// elsewhere in this provider (RSA, Ed25519, ML-DSA) — with SEC1 as a
// fallback so existing stored keys keep parsing without a migration.
func parseECDSAPrivateKey(ctx context.Context, op errors.Op, privDER []byte) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(privDER); err == nil {
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
				fmt.Sprintf("PKCS#8 key is not ECDSA: %T", key))
		}
		return ecKey, nil
	}

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

func signECDSAP256(ctx context.Context, privDER, payload []byte) ([]byte, error) {
	const op errors.Op = "software.signECDSAP256"

	privKey, err := parseECDSAPrivateKey(ctx, op, privDER)
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
func signECDSAP256Digest(ctx context.Context, privDER, digest []byte) ([]byte, error) {
	const op errors.Op = "software.signECDSAP256Digest"

	privKey, err := parseECDSAPrivateKey(ctx, op, privDER)
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
