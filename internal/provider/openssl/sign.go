package openssl

import (
	"context"
	stderrors "errors"

	"github.com/agile-crypto/ossl-go/ossl"

	"github.com/agile-crypto/citius-core/errors"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
)

// parsePrivateKey parses privDER as an asymmetric private key of the given
// encoding through libctx. Unlike software, this is one function for every
// algorithm rather than one per family: ossl-go's ParsePKCS8PrivateKey and
// ParseSEC1PrivateKey are generic, detecting the actual key type from the
// parsed structure rather than assuming one.
//
// Only the encodings this provider's own GenerateKey emits are handled —
// SEC1 (ECDSA) and PKCS8 (RSA, Ed25519, ML-DSA) — since nothing in this
// provider's own storage format needs anything else yet.
func parsePrivateKey(ctx context.Context, op errors.Op, libctx *ossl.Context, privDER []byte, encoding providerpb.PrivateKeyEncoding) (*ossl.Key, error) {
	switch encoding {
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1:
		key, err := libctx.ParseSEC1PrivateKey(privDER)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return key, nil
	case providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8:
		key, err := libctx.ParsePKCS8PrivateKey(privDER)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return key, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			"unsupported private key encoding: %s", encoding)
	}
}

// parsePublicKey parses pubDER as an SPKI-encoded public key through libctx —
// generic across algorithms the same way parsePrivateKey is, for the same
// reason.
//
// ML-DSA's RAW public key encoding is deliberately not handled here:
// ossl.Context.ParseRawPublicKey requires the caller to already know which
// KeyAlgorithm the bytes are (RAW carries no self-describing algorithm
// identifier the way SPKI's AlgorithmIdentifier does), so verifyMLDSA parses
// it directly with the algorithm mlDSAKeyAlgorithmFor resolves, rather than
// through this shared function.
func parsePublicKey(ctx context.Context, op errors.Op, libctx *ossl.Context, pubDER []byte, encoding providerpb.PublicKeyEncoding) (*ossl.Key, error) {
	switch encoding {
	case providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI:
		key, err := libctx.ParseSPKIPublicKey(pubDER)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return key, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			"unsupported public key encoding: %s", encoding)
	}
}

// verifyOutcome translates ossl.Key.Verify's three-way result (nil = valid,
// ErrVerification = well-formed but wrong, *Error = the call itself failed)
// into the (valid bool, error) shape every verifyXxx function returns —
// matching software's convention that a bad signature is never an error,
// only a genuine call failure is. ossl-go already collapses malformed
// signature bytes into ErrVerification itself (see Key.Verify's doc
// comment), so callers do not need their own malformed-bytes detection the
// way software's ECDSA path does with decodeECDSASignature.
func verifyOutcome(ctx context.Context, op errors.Op, err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	if stderrors.Is(err, ossl.ErrVerification) {
		return false, nil
	}
	return false, errors.Wrap(ctx, op, err)
}
