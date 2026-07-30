package software

import (
	"context"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	"github.com/agile-crypto/citius-server/internal/errors"
)

// mldsaScheme resolves the CIRCL generic sign.Scheme for a declared ML-DSA
// parameter set. AlgorithmDetails is authoritative for dispatch, the same
// convention checkCurveMatches/checkRSAKeySize apply elsewhere — a parameter
// set the caller declares but this provider does not implement is rejected
// outright rather than guessed at.
func mldsaScheme(ctx context.Context, op errors.Op, parameterSet types.MlDsaParameterSet) (sign.Scheme, error) {
	switch parameterSet {
	case types.MlDsaParameterSet_ML_DSA_44:
		return mldsa44.Scheme(), nil
	case types.MlDsaParameterSet_ML_DSA_65:
		return mldsa65.Scheme(), nil
	case types.MlDsaParameterSet_ML_DSA_87:
		return mldsa87.Scheme(), nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported ML-DSA parameter set: %s", parameterSet))
	}
}

func generateMLDSAKey(ctx context.Context, parameterSet types.MlDsaParameterSet) (pubBytes, privBytes []byte, _ error) {
	const op errors.Op = "software.generateMLDSAKey"

	scheme, err := mldsaScheme(ctx, op, parameterSet)
	if err != nil {
		return nil, nil, err
	}

	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	pubBytes, err = pub.MarshalBinary()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	privBytes, err = priv.MarshalBinary()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	return pubBytes, privBytes, nil
}

// signMLDSA signs payload with the ML-DSA private key encoded in privBytes.
//
// sign.Scheme.Sign is deterministic-only — every CIRCL ML-DSA scheme wrapper
// hardcodes randomized=false internally — so MlDsaParams.deterministic is
// not honored yet; a later commit adds the package-level SignTo dispatch
// needed for the hedged (randomized) case FIPS 204 recommends by default.
func signMLDSA(ctx context.Context, privBytes, payload []byte, parameterSet types.MlDsaParameterSet) ([]byte, error) {
	const op errors.Op = "software.signMLDSA"

	scheme, err := mldsaScheme(ctx, op, parameterSet)
	if err != nil {
		return nil, err
	}
	privKey, err := scheme.UnmarshalBinaryPrivateKey(privBytes)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return scheme.Sign(privKey, payload, nil), nil
}

func verifyMLDSA(ctx context.Context, pubBytes, payload, signature []byte, parameterSet types.MlDsaParameterSet) (bool, error) {
	const op errors.Op = "software.verifyMLDSA"

	scheme, err := mldsaScheme(ctx, op, parameterSet)
	if err != nil {
		return false, err
	}
	pubKey, err := scheme.UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		// Malformed stored public key — internal consistency error, not a sig failure.
		return false, errors.Wrap(ctx, op, err)
	}

	// scheme.Verify returns false for any invalid signature; it never errors.
	return scheme.Verify(pubKey, payload, signature, nil), nil
}
