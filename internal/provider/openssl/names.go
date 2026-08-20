package openssl

import (
	"context"
	"fmt"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	"github.com/agile-crypto/citius-server/internal/errors"
)

// keyAlgorithmFor maps an asymmetric AlgorithmDetails arm to the
// ossl.KeyAlgorithm (and, for EC, the ossl.Curve) that ossl.Context.GenerateKey
// needs.
//
// RsaPss and RsaPkcs1V15 both resolve to plain "RSA", not the scheme-locked
// "RSA-PSS" key type ossl-go also offers. "RSA-PSS" is more precise in
// isolation — that type structurally cannot produce a PKCS#1 v1.5 signature
// at all — but it costs real interop: OpenSSL correctly marshals it under
// the rsassaPss OID (1.2.840.113549.1.1.10) in PKCS#8/SPKI, and Go's
// stdlib crypto/x509 does not implement parsing that OID at all, so
// software (which always emits plain "RSA" under rsaEncryption,
// 1.2.840.113549.1.1.1) could never read openssl-generated PSS key
// material — verified directly: x509.ParsePKCS8PrivateKey fails outright
// on it. Plain "RSA" is what software already generates for both schemes,
// with the scheme chosen only at Sign() time (SignOptions.Padding), so
// that is what this function uses too, for both arms.
//
// Symmetric arms (AES*, ChaCha20-Poly1305) have no ossl.Key at all — their
// key material is raw bytes generated without this function — so they are
// an unsupported-arm error here, not a silent zero value.
func keyAlgorithmFor(ctx context.Context, op errors.Op, alg *types.AlgorithmDetails) (ossl.KeyAlgorithm, ossl.Curve, error) {
	switch a := alg.GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		curve, err := curveFor(ctx, op, a.Ecdsa.GetCurve())
		if err != nil {
			return "", "", err
		}
		return ossl.EC, curve, nil
	case *types.AlgorithmDetails_RsaPss, *types.AlgorithmDetails_RsaPkcs1V15:
		return ossl.RSA, "", nil
	case *types.AlgorithmDetails_Ed25519:
		return ossl.Ed25519, "", nil
	case *types.AlgorithmDetails_MlDsa:
		return mlDSAKeyAlgorithmFor(ctx, op, a.MlDsa.GetParameterSet())
	default:
		return "", "", errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for asymmetric key generation: %T", alg.GetAlgorithm()))
	}
}

// curveFor maps the typed EllipticCurve enum to ossl-go's Curve name.
//
// Only the NIST prime curves are implemented, matching the software
// provider's curveForAlgorithm scope. secp256k1, Curve25519/448 (used by
// Ed25519/X25519, not EcdsaParams), the Brainpool curves, and the binary
// K/B curves are valid per EcdsaParams.curve's proto constraint but are not
// supported here.
func curveFor(ctx context.Context, op errors.Op, curve types.EllipticCurve) (ossl.Curve, error) {
	switch curve {
	case types.EllipticCurve_ELLIPTIC_CURVE_P256:
		return ossl.P256, nil
	case types.EllipticCurve_ELLIPTIC_CURVE_P384:
		return ossl.P384, nil
	case types.EllipticCurve_ELLIPTIC_CURVE_P521:
		return ossl.P521, nil
	default:
		return "", errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported ECDSA curve: %s", curve))
	}
}

// mlDSAKeyAlgorithmFor maps the typed MlDsaParameterSet enum to ossl-go's
// per-parameter-set KeyAlgorithm name. ossl-go has no single "ML-DSA" key
// type plus a size option — the parameter set is baked into the name.
func mlDSAKeyAlgorithmFor(ctx context.Context, op errors.Op, ps types.MlDsaParameterSet) (ossl.KeyAlgorithm, ossl.Curve, error) {
	switch ps {
	case types.MlDsaParameterSet_ML_DSA_44:
		return ossl.MLDSA44, "", nil
	case types.MlDsaParameterSet_ML_DSA_65:
		return ossl.MLDSA65, "", nil
	case types.MlDsaParameterSet_ML_DSA_87:
		return ossl.MLDSA87, "", nil
	default:
		return "", "", errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported ML-DSA parameter set: %s", ps))
	}
}

// digestNameFor maps the typed HashAlgorithm enum to ossl-go's DigestName.
//
// UNSPECIFIED maps to "" deliberately, not an error: an empty
// ossl.SignOptions.Digest means "use the key-type default" in ossl-go's own
// API — Ed25519/ML-DSA hash internally and ignore it regardless, while
// ECDSA/RSA fall back to their own default digest. That is the same
// fallback contract HashAlgorithm's own proto doc declares for an unset
// hash, so leaving it empty here is a direct translation, not a guess.
func digestNameFor(ctx context.Context, op errors.Op, hash types.HashAlgorithm) (ossl.DigestName, error) {
	switch hash {
	case types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED:
		return "", nil
	case types.HashAlgorithm_HASH_ALGORITHM_SHA256:
		return ossl.SHA256, nil
	case types.HashAlgorithm_HASH_ALGORITHM_SHA384:
		return ossl.SHA384, nil
	case types.HashAlgorithm_HASH_ALGORITHM_SHA512:
		return ossl.SHA512, nil
	default:
		return "", errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported hash algorithm: %s", hash))
	}
}

// cipherNameFor maps a symmetric AlgorithmDetails arm to ossl-go's
// CipherName. Asymmetric arms are an unsupported-arm error here — the
// mirror image of keyAlgorithmFor.
func cipherNameFor(ctx context.Context, op errors.Op, alg *types.AlgorithmDetails) (ossl.CipherName, error) {
	switch a := alg.GetAlgorithm().(type) {
	case *types.AlgorithmDetails_AesGcm:
		return aesCipherNameFor(ctx, op, a.AesGcm.GetKeySizeBits(), aesGCMNames)
	case *types.AlgorithmDetails_AesCbc:
		return aesCipherNameFor(ctx, op, a.AesCbc.GetKeySizeBits(), aesCBCNames)
	case *types.AlgorithmDetails_AesCtr:
		return aesCipherNameFor(ctx, op, a.AesCtr.GetKeySizeBits(), aesCTRNames)
	case *types.AlgorithmDetails_Chacha20Poly1305:
		// XChaCha20-Poly1305 (the extended-nonce variant the software
		// provider calls "xchacha20-poly1305") has no ossl-go CipherName —
		// checked directly against the package's full constant list. A
		// request for it is an unsupported arm, not a silent fallback to
		// the IETF variant's different nonce semantics.
		if a.Chacha20Poly1305.GetExtendedNonce() {
			return "", errors.New(ctx, op, errors.CodeNotImplemented,
				"XChaCha20-Poly1305 (extended nonce) is not supported: ossl-go has no cipher name for it")
		}
		return ossl.ChaCha20Poly1305, nil
	default:
		return "", errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for cipher selection: %T", alg.GetAlgorithm()))
	}
}

var (
	aesGCMNames = map[uint32]ossl.CipherName{128: ossl.AES128GCM, 192: ossl.AES192GCM, 256: ossl.AES256GCM}
	aesCBCNames = map[uint32]ossl.CipherName{128: ossl.AES128CBC, 192: ossl.AES192CBC, 256: ossl.AES256CBC}
	aesCTRNames = map[uint32]ossl.CipherName{128: ossl.AES128CTR, 192: ossl.AES192CTR, 256: ossl.AES256CTR}
)

// aesCipherNameFor looks up the AES cipher name for keySizeBits in table,
// rejecting any size outside the three FIPS-197 options — the same
// defensive-allowlist convention the software provider applies via
// checkAESKeySize, since buf.validate does not run at this in-process layer.
func aesCipherNameFor(ctx context.Context, op errors.Op, keySizeBits uint32, table map[uint32]ossl.CipherName) (ossl.CipherName, error) {
	name, ok := table[keySizeBits]
	if !ok {
		return "", errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported AES key size: %d bits", keySizeBits))
	}
	return name, nil
}
