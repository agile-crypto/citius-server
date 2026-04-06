package software

import (
	"context"
	"crypto/rand"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.ibm.com/citius/citius-server/internal/errors"
)

func generateMLDSA65Key(ctx context.Context) (pubBytes, privBytes []byte, _ error) {
	const op errors.Op = "software.generateMLDSA65Key"

	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, op, err)
	}

	return pub.Bytes(), priv.Bytes(), nil
}

func signMLDSA65(ctx context.Context, privBytes, payload []byte) ([]byte, error) {
	const op errors.Op = "software.signMLDSA65"

	var privKey mldsa65.PrivateKey
	if err := privKey.UnmarshalBinary(privBytes); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// Deterministic ML-DSA-65: randomized=false, empty domain-separation context.
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&privKey, payload, nil, false, sig); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return sig, nil
}

func verifyMLDSA65(ctx context.Context, pubBytes, payload, signature []byte) (bool, error) {
	const op errors.Op = "software.verifyMLDSA65"

	var pubKey mldsa65.PublicKey
	if err := pubKey.UnmarshalBinary(pubBytes); err != nil {
		// Malformed stored public key — internal consistency error, not a sig failure.
		return false, errors.Wrap(ctx, op, err)
	}

	// mldsa65.Verify returns false for any invalid signature; it never errors.
	return mldsa65.Verify(&pubKey, payload, nil, signature), nil
}
