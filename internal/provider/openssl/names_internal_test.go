// This file is in package openssl rather than openssl_test — keyAlgorithmFor,
// curveFor, digestNameFor, and cipherNameFor are pure mapping functions with
// no exported entry point of their own; they are only reachable once GenerateKey/
// Sign/Encrypt dispatch on them in later commits. Testing them directly here,
// rather than waiting for that wiring, is what lets each mapping be reviewed
// and proven correct in isolation, matching the plan's intent for this commit.
package openssl

import (
	"context"
	"testing"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	"github.com/agile-crypto/citius-server/internal/errors"
)

const testOp errors.Op = "openssl.names_test"

func ecdsaDetails(curve types.EllipticCurve) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{Curve: curve},
		},
	}
}

func rsaPssDetails() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_RsaPss{RsaPss: &types.RsaPssParams{KeySizeBits: 2048}},
	}
}

func rsaPkcs1v15Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_RsaPkcs1V15{RsaPkcs1V15: &types.RsaPkcs1V15Params{KeySizeBits: 2048}},
	}
}

func ed25519Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ed25519{Ed25519: &types.Ed25519Params{}},
	}
}

func mlDSADetails(ps types.MlDsaParameterSet) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_MlDsa{MlDsa: &types.MlDsaParams{ParameterSet: ps}},
	}
}

func aesGCMDetails(keySizeBits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesGcm{AesGcm: &types.AesGcmParams{KeySizeBits: keySizeBits}},
	}
}

func aesCBCDetails(keySizeBits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesCbc{AesCbc: &types.AesCbcParams{KeySizeBits: keySizeBits}},
	}
}

func aesCTRDetails(keySizeBits uint32) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesCtr{AesCtr: &types.AesCtrParams{KeySizeBits: keySizeBits}},
	}
}

func chacha20Poly1305Details(extendedNonce bool) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Chacha20Poly1305{
			Chacha20Poly1305: &types.ChaCha20Poly1305Params{ExtendedNonce: extendedNonce},
		},
	}
}

func TestKeyAlgorithmFor(t *testing.T) {
	tests := []struct {
		name      string
		alg       *types.AlgorithmDetails
		wantAlg   ossl.KeyAlgorithm
		wantCurve ossl.Curve
	}{
		{"ecdsa p256", ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P256), ossl.EC, ossl.P256},
		{"ecdsa p384", ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P384), ossl.EC, ossl.P384},
		{"ecdsa p521", ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P521), ossl.EC, ossl.P521},
		// RSA-PSS and PKCS#1v1.5 both resolve to plain "RSA", not the
		// scheme-locked "RSA-PSS" key type — see keyAlgorithmFor's doc
		// comment for why: the scheme-locked type breaks cross-provider
		// interop (Go's stdlib x509 cannot parse it), so the scheme is
		// chosen at Sign() time instead, matching software.
		{"rsa pss", rsaPssDetails(), ossl.RSA, ""},
		{"rsa pkcs1v15", rsaPkcs1v15Details(), ossl.RSA, ""},
		{"ed25519", ed25519Details(), ossl.Ed25519, ""},
		{"ml-dsa-44", mlDSADetails(types.MlDsaParameterSet_ML_DSA_44), ossl.MLDSA44, ""},
		{"ml-dsa-65", mlDSADetails(types.MlDsaParameterSet_ML_DSA_65), ossl.MLDSA65, ""},
		{"ml-dsa-87", mlDSADetails(types.MlDsaParameterSet_ML_DSA_87), ossl.MLDSA87, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAlg, gotCurve, err := keyAlgorithmFor(context.Background(), testOp, tt.alg)
			if err != nil {
				t.Fatalf("keyAlgorithmFor: unexpected error: %v", err)
			}
			if gotAlg != tt.wantAlg {
				t.Errorf("algorithm: got %q want %q", gotAlg, tt.wantAlg)
			}
			if gotCurve != tt.wantCurve {
				t.Errorf("curve: got %q want %q", gotCurve, tt.wantCurve)
			}
		})
	}
}

// TestKeyAlgorithmFor_unsupported is the negative control: an arm this
// function has no case for (a symmetric algorithm, or an unsupported curve)
// must return CodeNotImplemented, never a zero-value KeyAlgorithm that a
// caller could mistake for a real answer.
func TestKeyAlgorithmFor_unsupported(t *testing.T) {
	tests := []struct {
		name string
		alg  *types.AlgorithmDetails
	}{
		{"symmetric arm (aes-gcm)", aesGCMDetails(256)},
		{"unset algorithm", &types.AlgorithmDetails{}},
		{"unsupported curve (secp256k1)", ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_SECP256K1)},
		{"unsupported ml-dsa parameter set", mlDSADetails(types.MlDsaParameterSet_ML_DSA_PARAMETER_SET_UNSPECIFIED)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAlg, gotCurve, err := keyAlgorithmFor(context.Background(), testOp, tt.alg)
			if !errors.IsNotImplemented(err) {
				t.Fatalf("expected CodeNotImplemented, got: %v", err)
			}
			if gotAlg != "" || gotCurve != "" {
				t.Errorf("expected zero-value results alongside the error, got algorithm=%q curve=%q", gotAlg, gotCurve)
			}
		})
	}
}

func TestDigestNameFor(t *testing.T) {
	tests := []struct {
		name string
		hash types.HashAlgorithm
		want ossl.DigestName
	}{
		{"unspecified maps to empty (key-type default)", types.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, ""},
		{"sha256", types.HashAlgorithm_HASH_ALGORITHM_SHA256, ossl.SHA256},
		{"sha384", types.HashAlgorithm_HASH_ALGORITHM_SHA384, ossl.SHA384},
		{"sha512", types.HashAlgorithm_HASH_ALGORITHM_SHA512, ossl.SHA512},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := digestNameFor(context.Background(), testOp, tt.hash)
			if err != nil {
				t.Fatalf("digestNameFor: unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q want %q", got, tt.want)
			}
		})
	}
}

// TestDigestNameFor_unsupported is the negative control: a hash this
// provider has no mapping for must error, not silently return "".
// UNSPECIFIED (tested above) is the only enum value "" is a correct answer
// for, so these must be rejected to prove UNSPECIFIED isn't just falling
// through a default case.
func TestDigestNameFor_unsupported(t *testing.T) {
	for _, hash := range []types.HashAlgorithm{
		types.HashAlgorithm_HASH_ALGORITHM_SHA3_256,
		types.HashAlgorithm_HASH_ALGORITHM_SHAKE128,
		types.HashAlgorithm_HASH_ALGORITHM_BLAKE2B_256,
	} {
		t.Run(hash.String(), func(t *testing.T) {
			got, err := digestNameFor(context.Background(), testOp, hash)
			if !errors.IsNotImplemented(err) {
				t.Fatalf("expected CodeNotImplemented, got: %v", err)
			}
			if got != "" {
				t.Errorf("expected empty result alongside the error, got %q", got)
			}
		})
	}
}

func TestCipherNameFor(t *testing.T) {
	tests := []struct {
		name string
		alg  *types.AlgorithmDetails
		want ossl.CipherName
	}{
		{"aes-128-gcm", aesGCMDetails(128), ossl.AES128GCM},
		{"aes-192-gcm", aesGCMDetails(192), ossl.AES192GCM},
		{"aes-256-gcm", aesGCMDetails(256), ossl.AES256GCM},
		{"aes-128-cbc", aesCBCDetails(128), ossl.AES128CBC},
		{"aes-192-cbc", aesCBCDetails(192), ossl.AES192CBC},
		{"aes-256-cbc", aesCBCDetails(256), ossl.AES256CBC},
		{"aes-128-ctr", aesCTRDetails(128), ossl.AES128CTR},
		{"aes-192-ctr", aesCTRDetails(192), ossl.AES192CTR},
		{"aes-256-ctr", aesCTRDetails(256), ossl.AES256CTR},
		{"chacha20-poly1305", chacha20Poly1305Details(false), ossl.ChaCha20Poly1305},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cipherNameFor(context.Background(), testOp, tt.alg)
			if err != nil {
				t.Fatalf("cipherNameFor: unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q want %q", got, tt.want)
			}
		})
	}
}

// TestCipherNameFor_unsupported is the negative control: an asymmetric arm,
// an AES key size outside the FIPS-197 set, and XChaCha20-Poly1305
// (extended nonce, which ossl-go has no name for) must all error rather
// than silently returning a plausible-looking but wrong CipherName.
func TestCipherNameFor_unsupported(t *testing.T) {
	tests := []struct {
		name string
		alg  *types.AlgorithmDetails
	}{
		{"asymmetric arm (ecdsa)", ecdsaDetails(types.EllipticCurve_ELLIPTIC_CURVE_P256)},
		{"unset algorithm", &types.AlgorithmDetails{}},
		{"unsupported aes key size", aesGCMDetails(512)},
		{"xchacha20-poly1305 (extended nonce)", chacha20Poly1305Details(true)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cipherNameFor(context.Background(), testOp, tt.alg)
			if !errors.IsNotImplemented(err) {
				t.Fatalf("expected CodeNotImplemented, got: %v", err)
			}
			if got != "" {
				t.Errorf("expected empty result alongside the error, got %q", got)
			}
		})
	}
}
