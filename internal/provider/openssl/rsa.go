package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	"github.com/agile-crypto/citius-server/internal/errors"
)

// generateRSAKey generates an RSA key pair through libctx, returning
// PKCS#8-encoded private bytes and SPKI-encoded public bytes — the same
// encodings software.generateRSAKey emits, so material either provider
// generates parses under the other's parser (proven in
// rsa_test.go's cross-provider interop test).
//
// algorithm comes from the caller via keyAlgorithmFor, which resolves both
// RsaPss and RsaPkcs1V15 templates to plain "RSA" — see its doc comment for
// why the scheme-locked "RSA-PSS" key type is deliberately not used despite
// being available. This function only does what is genuinely shared
// between the two templates: applying the bit size and marshaling the
// result.
func generateRSAKey(ctx context.Context, libctx *ossl.Context, algorithm ossl.KeyAlgorithm, bits uint32) (pubDER, privDER []byte, _ error) {
	const op errors.Op = "openssl.generateRSAKey"

	key, err := libctx.GenerateKey(algorithm, ossl.WithRSABits(int(bits)))
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

// generateRSAKeyForTemplate resolves the ossl-go key algorithm for details
// (via keyAlgorithmFor) and generates the key in one call, folding the
// "resolve, then generate" sequence RsaPss and RsaPkcs1V15 both need into a
// single call site — the shape every other case in
// Provider.GenerateKey's dispatch switch already has, and what keeps that
// switch's own complexity from growing with each algorithm family that
// needs an extra resolution step RSA's key-type split requires but ECDSA's
// single EC type does not.
func generateRSAKeyForTemplate(ctx context.Context, libctx *ossl.Context, details *types.AlgorithmDetails, bits uint32) (pubDER, privDER []byte, _ error) {
	const op errors.Op = "openssl.generateRSAKeyForTemplate"

	algorithm, _, err := keyAlgorithmFor(ctx, op, details)
	if err != nil {
		return nil, nil, err
	}
	return generateRSAKey(ctx, libctx, algorithm, bits)
}
