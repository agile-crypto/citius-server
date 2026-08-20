package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
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
