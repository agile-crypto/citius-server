package software

import (
	"context"
	"fmt"

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
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

// generateMLDSAKey generates an ML-DSA key pair, storing the private half as
// PKCS#8 wrapping the seed (FIPS 204's xi) rather than the full expanded
// private key. circl/pki.MarshalPKIXPrivateKey special-cases ML-DSA to do
// exactly this — draft-ietf-lamps-dilithium-certificates recommends the seed
// form for storage efficiency, since scheme.DeriveKey can always reconstruct
// the expanded key and public key from it. The public half has no such
// seed-vs-expanded distinction, so it stays in CIRCL's native packed form.
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
	privBytes, err = pki.MarshalPKIXPrivateKey(priv)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	return pubBytes, privBytes, nil
}

// parseMLDSAPrivateKey parses privBytes as an ML-DSA private key, dispatched
// on the declared encoding.
//
//   - PKCS8: the current storage format — a seed wrapped per
//     draft-ietf-lamps-dilithium-certificates, parsed and derived back into
//     a signing key by circl/pki.UnmarshalPKIXPrivateKey. The embedded OID
//     self-describes a scheme; that parsed scheme is cross-checked against
//     the one AlgorithmDetails declares rather than trusted on its own — the
//     same "declaration is authoritative, parsed data only validates it"
//     convention checkCurveMatches/checkRSAKeySize use elsewhere.
//   - RAW: the legacy expanded-key format every key generated before this
//     provider switched to PKCS#8 storage uses. Legacy keys can never be
//     upgraded to PKCS#8 — the expanded form does not carry the seed — so
//     this fallback is permanent, not a transitional shim.
//   - unspecified: legacy keys predate the encoding field entirely and so
//     carry no explicit value. Try PKCS#8 first; a successful parse (right
//     down to a matching scheme) is decisive on its own, a mismatched scheme
//     is a decisive config error, and only an outright parse failure falls
//     back to RAW — legacy expanded-key blobs are large, unstructured
//     lattice material with no realistic chance of also parsing as valid
//     PKCS#8 DER, so this fallback does not risk masking a real error the
//     way retrying a second *structured* encoding (as ECDSA's PKCS8-then-
//     SEC1 fallback must guard against) would.
func parseMLDSAPrivateKey(ctx context.Context, op errors.Op, privBytes []byte, encoding providerpb.PrivateKeyEncoding, scheme sign.Scheme, parameterSet types.MlDsaParameterSet) (sign.PrivateKey, error) {
	switch encoding {
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8:
		return parseMLDSAPKCS8PrivateKey(ctx, op, privBytes, scheme, parameterSet)
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW:
		privKey, err := scheme.UnmarshalBinaryPrivateKey(privBytes)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return privKey, nil
	default:
		if privKey, err := parseMLDSAPKCS8PrivateKey(ctx, op, privBytes, scheme, parameterSet); err == nil {
			return privKey, nil
		}
		privKey, err := scheme.UnmarshalBinaryPrivateKey(privBytes)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return privKey, nil
	}
}

func parseMLDSAPKCS8PrivateKey(ctx context.Context, op errors.Op, privBytes []byte, scheme sign.Scheme, parameterSet types.MlDsaParameterSet) (sign.PrivateKey, error) {
	privKey, err := pki.UnmarshalPKIXPrivateKey(privBytes)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if privKey.Scheme() != scheme {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"PKCS#8 key scheme %s does not match declared ML-DSA parameter set %s", privKey.Scheme().Name(), parameterSet)
	}
	return privKey, nil
}

// signMLDSA signs payload with the ML-DSA private key encoded in privBytes.
//
// sign.Scheme.Sign is deterministic-only — every CIRCL ML-DSA scheme wrapper
// hardcodes randomized=false internally — so honoring
// MlDsaParams.deterministic=false (proto3's zero value, matching FIPS 204
// -3.6's recommendation to prefer hedged/randomized signing) requires
// dropping to the package-level SignTo function instead, which does accept
// a randomized flag. That function is scheme-specific (mldsa44.SignTo vs
// mldsa65.SignTo vs mldsa87.SignTo), unlike everything else in this file
// that stays generic over sign.Scheme, so it needs its own per-parameter-set
// dispatch — see signMLDSARandomized.
func signMLDSA(ctx context.Context, privBytes, payload []byte, keyEncoding providerpb.PrivateKeyEncoding, parameterSet types.MlDsaParameterSet, deterministic bool) ([]byte, error) {
	const op errors.Op = "software.signMLDSA"

	scheme, err := mldsaScheme(ctx, op, parameterSet)
	if err != nil {
		return nil, err
	}
	privKey, err := parseMLDSAPrivateKey(ctx, op, privBytes, keyEncoding, scheme, parameterSet)
	if err != nil {
		return nil, err
	}
	if deterministic {
		return scheme.Sign(privKey, payload, nil), nil
	}
	return signMLDSARandomized(ctx, op, privKey, payload, parameterSet)
}

// signMLDSARandomized performs hedged (randomized) ML-DSA signing via the
// scheme-specific package-level SignTo function — see signMLDSA for why
// sign.Scheme.Sign cannot do this. privKey must be the concrete private key
// type SignTo for parameterSet expects; parseMLDSAPrivateKey always returns
// exactly that type for a given parameterSet, since it derives from
// mldsaScheme(parameterSet) itself, so the type assertions below cannot fail
// in practice.
func signMLDSARandomized(ctx context.Context, op errors.Op, privKey sign.PrivateKey, payload []byte, parameterSet types.MlDsaParameterSet) ([]byte, error) {
	switch parameterSet {
	case types.MlDsaParameterSet_ML_DSA_44:
		sk, ok := privKey.(*mldsa44.PrivateKey)
		if !ok {
			return nil, errors.New(ctx, op, errors.CodeInternal, "ML-DSA-44 private key has unexpected type %T", privKey)
		}
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(sk, payload, nil, true, sig); err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return sig, nil
	case types.MlDsaParameterSet_ML_DSA_65:
		sk, ok := privKey.(*mldsa65.PrivateKey)
		if !ok {
			return nil, errors.New(ctx, op, errors.CodeInternal, "ML-DSA-65 private key has unexpected type %T", privKey)
		}
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(sk, payload, nil, true, sig); err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return sig, nil
	case types.MlDsaParameterSet_ML_DSA_87:
		sk, ok := privKey.(*mldsa87.PrivateKey)
		if !ok {
			return nil, errors.New(ctx, op, errors.CodeInternal, "ML-DSA-87 private key has unexpected type %T", privKey)
		}
		sig := make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(sk, payload, nil, true, sig); err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return sig, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			"unsupported ML-DSA parameter set: %s", parameterSet)
	}
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
