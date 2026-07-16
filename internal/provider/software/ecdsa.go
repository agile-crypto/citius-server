package software

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"

	"github.com/agile-crypto/citius-server/internal/errors"
)

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

	privKey, err := x509.ParseECPrivateKey(privDER)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:])
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
