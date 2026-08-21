package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
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
// (via keyAlgorithmFor) and generates the key in one call
func generateRSAKeyForTemplate(ctx context.Context, libctx *ossl.Context, details *types.AlgorithmDetails, bits uint32) (pubDER, privDER []byte, _ error) {
	const op errors.Op = "openssl.generateRSAKeyForTemplate"

	algorithm, _, err := keyAlgorithmFor(ctx, op, details)
	if err != nil {
		return nil, nil, err
	}
	return generateRSAKey(ctx, libctx, algorithm, bits)
}

// checkRSAKeySize cross-checks a parsed key's actual modulus size against
// the size AlgorithmDetails declares — the RSA analogue of ecdsa.go's
// checkCurveMatches, catching a stored key that has drifted from its
// declaration.
func checkRSAKeySize(ctx context.Context, op errors.Op, key *ossl.Key, declaredBits uint32) error {
	if actual := key.Bits(); actual != int(declaredBits) {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"key size %d bits does not match declared algorithm key size %d bits", actual, declaredBits)
	}
	return nil
}

// checkRSAPSSMGF validates the declared mask generation function and MGF
// hash — mirrors software's checkRSAPSSMGF's restriction even though
// ossl-go's SignOptions.MGF1Hash could, in principle, support an
// independent MGF hash: keeping the same restriction here means a given
// template behaves identically regardless of which provider serves it,
// rather than this provider silently accepting more than software (and
// therefore more than has ever been tested) does.
func checkRSAPSSMGF(ctx context.Context, op errors.Op, mgf types.MaskGenerationFunction, hash, mgfHash types.HashAlgorithm) error {
	if mgf != types.MaskGenerationFunction_MGF_UNSPECIFIED && mgf != types.MaskGenerationFunction_MGF_MGF1 {
		return errors.New(ctx, op, errors.CodeNotImplemented, "unsupported RSA-PSS mask generation function: %s", mgf)
	}
	if mgfHash != types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED && mgfHash != hash {
		return errors.New(ctx, op, errors.CodeNotImplemented,
			"RSA-PSS with mgf_hash (%s) different from hash (%s) is not supported", mgfHash, hash)
	}
	return nil
}

// rsaPSSSaltLength maps RsaPssParams.salt_length_mode/salt_length_bytes to
// ossl.PSSSaltLength.
func rsaPSSSaltLength(ctx context.Context, op errors.Op, mode types.RsaPssParams_SaltLengthMode, explicitBytes uint32) (ossl.PSSSaltLength, error) {
	switch mode {
	case types.RsaPssParams_SALT_LENGTH_MODE_HASH_LENGTH:
		return ossl.PSSSaltLengthHash, nil
	case types.RsaPssParams_SALT_LENGTH_MODE_MAX:
		return ossl.PSSSaltLengthMax, nil
	case types.RsaPssParams_SALT_LENGTH_MODE_EXPLICIT:
		if explicitBytes == 0 {
			return 0, errors.New(ctx, op, errors.CodeInvalidArgument, "SALT_LENGTH_MODE_EXPLICIT requires salt_length_bytes > 0")
		}
		return ossl.PSSSaltLength(explicitBytes), nil
	default:
		return 0, errors.New(ctx, op, errors.CodeNotImplemented, "unsupported RSA-PSS salt length mode: %s", mode)
	}
}

// rsaHashName resolves the typed HashAlgorithm to ossl.DigestName,
// restricted to exactly what RsaPssParams.hash's proto constraint allows,
// with an explicit SHA-256 default rather than relying on ossl-go's own
// RSA default digest (unverified here to be SHA-256), matching the proto's
// documented default ("Hash algorithm. Default: SHA-256") exactly.
func rsaHashName(ctx context.Context, op errors.Op, hash types.HashAlgorithm) (ossl.DigestName, error) {
	switch hash {
	case types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, types.HashAlgorithm_HASH_ALGORITHM_SHA256:
		return ossl.SHA256, nil
	case types.HashAlgorithm_HASH_ALGORITHM_SHA384:
		return ossl.SHA384, nil
	case types.HashAlgorithm_HASH_ALGORITHM_SHA512:
		return ossl.SHA512, nil
	default:
		return "", errors.New(ctx, op, errors.CodeNotImplemented, "unsupported RSA hash algorithm: %s", hash)
	}
}

// signRSAPSS signs payload with the RSA-PSS private key in privDER. Key.Sign
// hashes payload internally under digest — unlike software, there is no
// separate pre-hashing step here.
func signRSAPSS(ctx context.Context, libctx *ossl.Context, privDER, payload []byte, keyEncoding providerpb.PrivateKeyEncoding, params *types.RsaPssParams) ([]byte, error) {
	const op errors.Op = "openssl.signRSAPSS"

	key, err := parsePrivateKey(ctx, op, libctx, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	if err = checkRSAKeySize(ctx, op, key, params.GetKeySizeBits()); err != nil {
		return nil, err
	}
	if err = checkRSAPSSMGF(ctx, op, params.GetMgf(), params.GetHash(), params.GetMgfHash()); err != nil {
		return nil, err
	}
	digest, err := rsaHashName(ctx, op, params.GetHash())
	if err != nil {
		return nil, err
	}
	saltLen, err := rsaPSSSaltLength(ctx, op, params.GetSaltLengthMode(), params.GetSaltLengthBytes())
	if err != nil {
		return nil, err
	}

	sig, err := key.Sign(payload, &ossl.SignOptions{Digest: digest, Padding: ossl.RSAPSS, PSSSaltLen: saltLen})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

// signRSAPKCS1v15 signs payload with the RSA private key in privDER using
// PKCS#1 v1.5 padding. Padding must be set explicitly — ossl-go defaults to
// PSS deliberately (see SignOptions.Padding's doc comment), so leaving it
// unset here would silently sign under the wrong scheme.
func signRSAPKCS1v15(ctx context.Context, libctx *ossl.Context, privDER, payload []byte, keyEncoding providerpb.PrivateKeyEncoding, params *types.RsaPkcs1V15Params) ([]byte, error) {
	const op errors.Op = "openssl.signRSAPKCS1v15"

	key, err := parsePrivateKey(ctx, op, libctx, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	if err = checkRSAKeySize(ctx, op, key, params.GetKeySizeBits()); err != nil {
		return nil, err
	}
	digest, err := rsaHashName(ctx, op, params.GetHash())
	if err != nil {
		return nil, err
	}

	sig, err := key.Sign(payload, &ossl.SignOptions{Digest: digest, Padding: ossl.RSAPKCS1v15})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}
