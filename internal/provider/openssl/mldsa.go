package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	"github.com/agile-crypto/citius-server/internal/errors"
)

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
