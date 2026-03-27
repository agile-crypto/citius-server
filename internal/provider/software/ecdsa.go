package software

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.ibm.com/citius/citius-server/internal/errors"
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
