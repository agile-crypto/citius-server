package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
)

// mldsaMaxContextLen is the longest domain separation context FIPS 204
// §3.2 permits — the same bound software.mldsaMaxContextLen uses.
const mldsaMaxContextLen = 255

// checkMLDSAContextLength rejects an over-long domain separation context
// with CodeInvalidArgument before it reaches Key.Sign.
//
// ossl-go's own SignOptions validation already rejects this safely (a plain
// error, not a panic — unlike the CIRCL panic risk that motivates
// software's identical check), so this is not a crash-prevention measure
// the way software's is. It exists so the error code matches: without it,
// the rejection would come back wrapped as ossl-go's generic error
// (CodeInternal by default) instead of CodeInvalidArgument, and the same
// malformed request would be categorized differently depending on which
// provider served it.
func checkMLDSAContextLength(ctx context.Context, op errors.Op, domainContext []byte) error {
	if len(domainContext) > mldsaMaxContextLen {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"domain separation context is %d bytes, exceeds the %d-byte maximum", len(domainContext), mldsaMaxContextLen)
	}
	return nil
}

// generateMLDSAKey generates an ML-DSA key pair for parameterSet through
// libctx, returning PKCS#8-encoded private bytes and raw public bytes
//
//   - Private key: software's ML-DSA private half is a PKCS#8-wrapped
//     32-byte seed (draft-ietf-lamps-dilithium-certificates' seed-only
//     CHOICE); OpenSSL's PKCS8 output for ML-DSA is larger (4098 bytes for
//     ML-DSA-65) because it uses the draft's "both" CHOICE — seed and
//     expanded key together — not, as a byte-length comparison alone would
//     suggest, an expanded-key-only encoding incompatible with the seed
//     form. CIRCL's parser (github.com/cloudflare/circl/pki) explicitly
//     supports both the seed-only and the "both" CHOICE, deriving from the
//     seed and cross-validating against the expanded key when present, so
//     it reads OpenSSL's output directly. The reverse direction works too:
//     ossl-go's generic ParsePKCS8PrivateKey accepts software's seed-only
//     PKCS8 without any ML-DSA-specific handling on this side.
//   - Public key: MarshalSPKI, not MarshalRawPublicKey, is what every other
//     algorithm in this file uses — but software has no SPKI parser for
//     ML-DSA at all, only CIRCL's raw packed format (UnmarshalBinaryPublicKey).
//     Declaring SPKI here would break interop on the public-key
//     side even though the private-key side works. MarshalRawPublicKey is
//     used instead to match CIRCL's raw layout byte-for-byte
//     in both directions.
func generateMLDSAKey(ctx context.Context, libctx *ossl.Context, parameterSet types.MlDsaParameterSet) (pubDER, privDER []byte, _ error) {
	const op errors.Op = "openssl.generateMLDSAKey"

	algorithm, _, err := mlDSAKeyAlgorithmFor(ctx, op, parameterSet)
	if err != nil {
		return nil, nil, err
	}

	key, err := libctx.GenerateKey(algorithm)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	defer key.Close()

	pubDER, err = key.MarshalRawPublicKey()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	privDER, err = key.MarshalPKCS8()
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}
	return pubDER, privDER, nil
}

// signMLDSA signs payload with the ML-DSA private key in privDER, honoring
// the caller-supplied domain separation context (FIPS 204 §3.2) and
// deterministic/hedged choice.
//
// Unlike software — which dispatches deterministic signing to
// sign.Scheme.Sign and hedged signing to a separate, scheme-specific
// package-level SignTo function, because CIRCL exposes no single call that
// does both — ossl-go's Key.Sign handles both through the same call,
// selected by SignOptions.Deterministic.
func signMLDSA(ctx context.Context, libctx *ossl.Context, privDER, payload, domainContext []byte, keyEncoding providerpb.PrivateKeyEncoding, parameterSet types.MlDsaParameterSet, deterministic bool) ([]byte, error) {
	const op errors.Op = "openssl.signMLDSA"

	if err := checkMLDSAContextLength(ctx, op, domainContext); err != nil {
		return nil, err
	}
	algorithm, _, err := mlDSAKeyAlgorithmFor(ctx, op, parameterSet)
	if err != nil {
		return nil, err
	}
	key, err := parsePrivateKey(ctx, op, libctx, privDER, keyEncoding)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	if key.Type() != algorithm {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"key type %s does not match declared algorithm %s", key.Type(), algorithm)
	}

	sig, err := key.Sign(payload, &ossl.SignOptions{Context: domainContext, Deterministic: deterministic})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

// verifyMLDSA verifies signature over payload with the ML-DSA public key in
// pubBytes, honoring the same domain separation context Sign does.
//
// pubBytes is parsed with ParseRawPublicKey rather than the shared
// parsePublicKey: RAW is not self-describing the way SPKI is, so the
// algorithm resolved from parameterSet is what tells ossl-go which ML-DSA
// variant these bytes are -- see generateMLDSAKey's doc comment for why RAW
// is this algorithm's public key encoding at all.
func verifyMLDSA(ctx context.Context, libctx *ossl.Context, pubBytes, payload, signature, domainContext []byte, parameterSet types.MlDsaParameterSet) (bool, error) {
	const op errors.Op = "openssl.verifyMLDSA"

	if err := checkMLDSAContextLength(ctx, op, domainContext); err != nil {
		return false, err
	}
	algorithm, _, err := mlDSAKeyAlgorithmFor(ctx, op, parameterSet)
	if err != nil {
		return false, err
	}
	key, err := libctx.ParseRawPublicKey(algorithm, pubBytes)
	if err != nil {
		// Malformed stored public key -- internal consistency error, not a
		// signature failure -- same distinction software's verifyMLDSA draws.
		return false, errors.Wrap(ctx, op, err)
	}
	defer key.Close()

	if key.Type() != algorithm {
		return false, errors.New(ctx, op, errors.CodeInvalidArgument,
			"key type %s does not match declared algorithm %s", key.Type(), algorithm)
	}

	return verifyOutcome(ctx, op, key.Verify(payload, signature, &ossl.SignOptions{Context: domainContext}))
}
