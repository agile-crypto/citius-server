// Package openssl implements a provider.Backend backed by OpenSSL 3.5
// libcrypto via github.com/agile-crypto/ossl-go.
//
// Mode — default, FIPS — is a property of which
// *ossl.Context a Provider instance wraps, not a runtime flag: an isolated
// OSSL_LIB_CTX has its own provider set, default property query, and DRBG
// state, independent of every other context. New builds the default-mode
// context; WithFIPS builds one restricted to the validated module the same
// way, through options — each mode registered under its own
// provider.Registry name so the existing key-to-provider routing
// (KeyVersion.ProviderId) binds every later operation on a key back to the
// exact context that created it.
//
// This package compiles under CGO_ENABLED=0: ossl-go ships a no-cgo mirror
// that returns ossl.ErrUnavailable from every operation rather than failing
// to build. New's ossl.CheckVersion call surfaces that at construction time,
// so a nocgo build fails to construct this provider instead of registering
// one that errors on every call.
package openssl

import (
	"context"
	"fmt"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider"
)

// defaultName is the provider.Registry identity used when no WithName option
// is supplied — the default-mode instance's expected name (see wire.go).
const defaultName = "openssl"

// Provider is a provider.Backend implementation backed by an OpenSSL library
// context. It is stateless with respect to key material — every operation
// parses caller-supplied bytes into a fresh *ossl.Key, uses it, and closes
// it — but it owns the *ossl.Context for its entire lifetime, because the
// context (not the Provider) is what carries mode.
type Provider struct {
	name   string
	libctx *ossl.Context
	// algs is this instance's SupportedAlgorithms result, derived once at
	// construction from catalog against libctx — see capability.go.
	algs []string
}

// New constructs a Provider using an isolated OpenSSL library context —
// FIPS-restricted if WithFIPS is given, the default provider set otherwise.
//
// It fails if the runtime libcrypto does not match the library this
// package was built against.
func New(ctx context.Context, opts ...Option) (*Provider, error) {
	const op errors.Op = "openssl.New"

	if err := ossl.CheckVersion(); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	cfg := &config{name: defaultName}
	for _, opt := range opts {
		opt(cfg)
	}

	var libctx *ossl.Context
	var err error
	if cfg.fipsConfigPath != "" {
		libctx, err = ossl.NewFIPSContext(cfg.fipsConfigPath)
	} else {
		libctx, err = ossl.NewContext()
	}
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// EnableFIPS (which NewFIPSContext calls) only reports FIPSEnabled true
	// on a path that already succeeded, so this cannot fail given a correct
	// ossl-go — it exists as a self-check specifically because a FIPS
	// context that looks restricted and is not is the one failure mode in
	// this area that fails silently rather than with an error. Close before
	// returning: a failed New must not leak the context it just created.
	if cfg.fipsConfigPath != "" && !libctx.FIPSEnabled() {
		libctx.Close()
		return nil, errors.New(ctx, op, errors.CodeUnavailable,
			"FIPS context construction reported success but the context is not FIPS-restricted")
	}

	return &Provider{name: cfg.name, libctx: libctx, algs: deriveAlgorithms(libctx, catalog)}, nil
}

// Name returns the provider's registry identity — distinct per mode instance
// (e.g. "openssl", "openssl-fips") so several coexist in the same registry.
func (p *Provider) Name() string { return p.name }

// Type returns the provider kind. Every mode instance shares this value;
// Name is what distinguishes them. Type has no caller in this codebase today
// beyond identity display, so one shared value for every mode is safe.
func (p *Provider) Type() string { return "openssl" }

// Close releases the OpenSSL library context this Provider owns.
//
// provider.Backend has no shutdown hook, so a registered instance's context
// lives for the process lifetime in practice. Close exists for tests and for
// a future server-shutdown path.
func (p *Provider) Close() error {
	return p.libctx.Close()
}

// FIPSEnabled reports whether this instance's context is restricted to the
// FIPS provider — true for an instance built with WithFIPS, false otherwise.
func (p *Provider) FIPSEnabled() bool {
	return p.libctx.FIPSEnabled()
}

// GenerateKey dispatches to the algorithm-specific key generator. Structure
// mirrors software.Provider.GenerateKey: each case sets the shared
// pubDER/privDER/encoding variables and falls through to one response
// construction, rather than each case building its own.
func (p *Provider) GenerateKey(ctx context.Context, req *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	const op errors.Op = "openssl.(Provider).GenerateKey"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}

	var (
		pubDER  []byte
		privDER []byte
		privEnc providerpb.PrivateKeyEncoding
		pubEnc  providerpb.PublicKeyEncoding
		err     error
	)

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		pubDER, privDER, err = generateECDSAKey(ctx, p.libctx, alg.Ecdsa.GetCurve())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		// The two halves differ: SEC1 (RFC 5915) for the private key, SPKI
		// (RFC 5280) for the public key — the same split software's ECDSA
		// path uses, for the same reason (see generateECDSAKey's doc).
		privEnc = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_SEC1
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI
	case *types.AlgorithmDetails_RsaPss:
		pubDER, privDER, err = generateRSAKeyForTemplate(ctx, p.libctx, req.GetAlgorithm(), alg.RsaPss.GetKeySizeBits())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		privEnc = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI
	case *types.AlgorithmDetails_RsaPkcs1V15:
		pubDER, privDER, err = generateRSAKeyForTemplate(ctx, p.libctx, req.GetAlgorithm(), alg.RsaPkcs1V15.GetKeySizeBits())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		privEnc = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI
	case *types.AlgorithmDetails_Ed25519:
		pubDER, privDER, err = generateEd25519Key(ctx, p.libctx)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		privEnc = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI
	case *types.AlgorithmDetails_MlDsa:
		pubDER, privDER, err = generateMLDSAKey(ctx, p.libctx, alg.MlDsa.GetParameterSet())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		// Public half is RAW here, not SPKI like every other case in this
		// switch -- see generateMLDSAKey's doc comment: software has no
		// SPKI parser for ML-DSA, only CIRCL's raw packed format, so RAW is
		// what makes this genuinely interoperate rather than what would be
		// the more obvious choice by analogy with ECDSA/RSA/Ed25519.
		privEnc = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_RAW
	case *types.AlgorithmDetails_AesGcm, *types.AlgorithmDetails_AesCbc, *types.AlgorithmDetails_AesCtr, *types.AlgorithmDetails_Chacha20Poly1305:
		privDER, err = generateSymmetricKey(ctx, req.GetAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		// Symmetric: no public half -- pubDER/pubEnc stay at their zero values.
		privEnc = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_RAW
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm type: %T", req.GetAlgorithm().GetAlgorithm()))
	}

	return &providerpb.GenerateKeyResponse{
		PublicKeyBytes:      pubDER,
		KeyMaterial:         privDER,
		Output:              provider.NoOutputUnencoded(),
		KeyMaterialEncoding: privEnc,
		PublicKeyEncoding:   pubEnc,
	}, nil
}

// Sign dispatches to the algorithm-specific sign implementation.
func (p *Provider) Sign(ctx context.Context, req *providerpb.SignRequest) (*providerpb.SignResponse, error) {
	const op errors.Op = "openssl.(Provider).Sign"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		sig, err := signECDSA(ctx, p.libctx, req.GetKeyMaterial(), req.GetInput(), req.GetKeyMaterialEncoding(),
			alg.Ecdsa.GetCurve(), alg.Ecdsa.GetHash(), alg.Ecdsa.GetSignatureFormat())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput(ecdsaSignatureEncodingLabel(alg.Ecdsa.GetSignatureFormat()))}, nil
	case *types.AlgorithmDetails_MlDsa:
		sig, err := signMLDSA(ctx, p.libctx, req.GetKeyMaterial(), req.GetInput(), req.GetDomainContext().GetContext(),
			req.GetKeyMaterialEncoding(), alg.MlDsa.GetParameterSet(), alg.MlDsa.GetDeterministic())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	case *types.AlgorithmDetails_RsaPss:
		sig, err := signRSAPSS(ctx, p.libctx, req.GetKeyMaterial(), req.GetInput(), req.GetKeyMaterialEncoding(), alg.RsaPss)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	case *types.AlgorithmDetails_RsaPkcs1V15:
		sig, err := signRSAPKCS1v15(ctx, p.libctx, req.GetKeyMaterial(), req.GetInput(), req.GetKeyMaterialEncoding(), alg.RsaPkcs1V15)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	case *types.AlgorithmDetails_Ed25519:
		sig, err := signEd25519(ctx, p.libctx, req.GetKeyMaterial(), req.GetInput(), req.GetKeyMaterialEncoding(), alg.Ed25519.GetVariant())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for sign: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// Verify dispatches to the algorithm-specific verify implementation.
func (p *Provider) Verify(ctx context.Context, req *providerpb.VerifyRequest) (*providerpb.VerifyResponse, error) {
	const op errors.Op = "openssl.(Provider).Verify"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		valid, err := verifyECDSA(ctx, p.libctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), alg.Ecdsa.GetCurve(), alg.Ecdsa.GetHash(), alg.Ecdsa.GetSignatureFormat())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_MlDsa:
		valid, err := verifyMLDSA(ctx, p.libctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature(),
			req.GetDomainContext().GetContext(), alg.MlDsa.GetParameterSet())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_RsaPss:
		valid, err := verifyRSAPSS(ctx, p.libctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature(), req.GetKeyMaterialEncoding(), alg.RsaPss)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_RsaPkcs1V15:
		valid, err := verifyRSAPKCS1v15(ctx, p.libctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature(), req.GetKeyMaterialEncoding(), alg.RsaPkcs1V15)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_Ed25519:
		valid, err := verifyEd25519(ctx, p.libctx, req.GetKeyMaterial(), req.GetInput(), req.GetSignature(), req.GetKeyMaterialEncoding(), alg.Ed25519.GetVariant())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for verify: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// validateDigestLength rejects a digest whose length contradicts the
// declared hash algorithm (e.g. a 20-byte digest claiming to be SHA-256,
// which must be 32 bytes). Hash algorithms with no fixed length
// (UNSPECIFIED, OTHER, the SHAKE XOFs) are not checked — the caller declared
// no fixed-length hash, so there is nothing to validate the digest against.
//
// Mirrors software.validateDigestLength exactly, sharing the same
// provider.DigestLengthForHash table, so a malformed request is rejected
// identically regardless of which provider serves it.
func validateDigestLength(ctx context.Context, op errors.Op, hashAlg types.HashAlgorithm, digestLen int) error {
	wantLen, ok := provider.DigestLengthForHash(hashAlg)
	if !ok {
		return nil
	}
	if digestLen != wantLen {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"digest length %d bytes does not match expected length %d bytes for %s", digestLen, wantLen, hashAlg)
	}
	return nil
}

// SignDigest signs a pre-computed digest — the provider does NOT hash.
// Dispatches on the typed AlgorithmDetails oneof, exactly like Sign; the
// digest and key material alone cannot select the signature scheme (a single
// RSA key is valid under both PSS and PKCS1v15), so hash_algorithm describes
// only the digest's origin, never the algorithm to dispatch on.
//
// Unlike Sign, which always calls Key.Sign (EVP_DigestSign — hashes
// internally), every arm here calls Key.SignDigest (EVP_PKEY_sign — signs
// the given bytes as-is). Routing a caller-supplied digest through Key.Sign
// would hash it a second time and silently produce a signature over the
// wrong statement; see SignDigestRequest's doc comment in the provider proto
// for the full rationale.
func (p *Provider) SignDigest(ctx context.Context, req *providerpb.SignDigestRequest) (*providerpb.SignDigestResponse, error) {
	const op errors.Op = "openssl.(Provider).SignDigest"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}
	if err := validateDigestLength(ctx, op, req.GetHashAlgorithm(), len(req.GetDigest())); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		sig, err := signECDSADigest(ctx, p.libctx, req.GetKeyMaterial(), req.GetDigest(), req.GetKeyMaterialEncoding(),
			alg.Ecdsa.GetCurve(), req.GetHashAlgorithm(), alg.Ecdsa.GetSignatureFormat())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignDigestResponse{Signature: sig, Output: provider.NoOutput(ecdsaSignatureEncodingLabel(alg.Ecdsa.GetSignatureFormat()))}, nil
	case *types.AlgorithmDetails_MlDsa:
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"SignDigest unsupported for ML-DSA: pure ML-DSA is not prehashable")
	case *types.AlgorithmDetails_RsaPss:
		sig, err := signRSAPSSDigest(ctx, p.libctx, req.GetKeyMaterial(), req.GetDigest(), req.GetKeyMaterialEncoding(),
			req.GetHashAlgorithm(), alg.RsaPss)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignDigestResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	case *types.AlgorithmDetails_RsaPkcs1V15:
		sig, err := signRSAPKCS1v15Digest(ctx, p.libctx, req.GetKeyMaterial(), req.GetDigest(), req.GetKeyMaterialEncoding(),
			req.GetHashAlgorithm(), alg.RsaPkcs1V15)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignDigestResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	case *types.AlgorithmDetails_Ed25519:
		if alg.Ed25519.GetVariant() != types.Ed25519Variant_ED25519_VARIANT_UNSPECIFIED &&
			alg.Ed25519.GetVariant() != types.Ed25519Variant_ED25519_VARIANT_PH {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
				"SignDigest requires Ed25519ph: pure Ed25519 and Ed25519ctx are not prehashable")
		}
		sig, err := signEd25519PHDigest(ctx, p.libctx, req.GetKeyMaterial(), req.GetDigest(), req.GetKeyMaterialEncoding(), req.GetHashAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.SignDigestResponse{Signature: sig, Output: provider.NoOutput("raw")}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for digest sign: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// VerifyDigest verifies a signature over a pre-computed digest — the
// provider does NOT hash. Mirror of SignDigest on the verify side: same
// non-prehashable rejections, same digest-length validation, and every arm
// calls Key.VerifyDigest (EVP_PKEY_verify) rather than Key.Verify
// (EVP_DigestVerify), for the same reason SignDigest calls Key.SignDigest.
func (p *Provider) VerifyDigest(ctx context.Context, req *providerpb.VerifyDigestRequest) (*providerpb.VerifyDigestResponse, error) {
	const op errors.Op = "openssl.(Provider).VerifyDigest"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}
	if err := validateDigestLength(ctx, op, req.GetHashAlgorithm(), len(req.GetDigest())); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_Ecdsa:
		valid, err := verifyECDSADigest(ctx, p.libctx, req.GetKeyMaterial(), req.GetDigest(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), alg.Ecdsa.GetCurve(), req.GetHashAlgorithm(), alg.Ecdsa.GetSignatureFormat())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyDigestResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_MlDsa:
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"VerifyDigest unsupported for ML-DSA: pure ML-DSA is not prehashable")
	case *types.AlgorithmDetails_RsaPss:
		valid, err := verifyRSAPSSDigest(ctx, p.libctx, req.GetKeyMaterial(), req.GetDigest(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), req.GetHashAlgorithm(), alg.RsaPss)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyDigestResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_RsaPkcs1V15:
		valid, err := verifyRSAPKCS1v15Digest(ctx, p.libctx, req.GetKeyMaterial(), req.GetDigest(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), req.GetHashAlgorithm(), alg.RsaPkcs1V15)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyDigestResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_Ed25519:
		if alg.Ed25519.GetVariant() != types.Ed25519Variant_ED25519_VARIANT_UNSPECIFIED &&
			alg.Ed25519.GetVariant() != types.Ed25519Variant_ED25519_VARIANT_PH {
			return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
				"VerifyDigest requires Ed25519ph: pure Ed25519 and Ed25519ctx are not prehashable")
		}
		valid, err := verifyEd25519PHDigest(ctx, p.libctx, req.GetKeyMaterial(), req.GetDigest(), req.GetSignature(),
			req.GetKeyMaterialEncoding(), req.GetHashAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.VerifyDigestResponse{Valid: valid, Output: provider.NoOutputUnencoded()}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for digest verify: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// Encrypt dispatches to the algorithm-specific encrypt implementation.
// AES-CBC and AES-CTR are implemented; AES-GCM and ChaCha20-Poly1305 (AEAD)
// are a separate, later commit and still fall through to the default case.
func (p *Provider) Encrypt(ctx context.Context, req *providerpb.EncryptRequest) (*providerpb.EncryptResponse, error) {
	const op errors.Op = "openssl.(Provider).Encrypt"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_AesGcm:
		name, err := cipherNameFor(ctx, op, req.GetAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		ciphertext, nonce, err := encryptAESGCM(ctx, p.libctx, name, req.GetKeyMaterial(), req.GetPlaintext(), req.GetAeadParams().GetAad(), alg.AesGcm)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.EncryptResponse{
			Ciphertext: ciphertext,
			Output:     provider.AeadOutput(nonce, alg.AesGcm.GetTagSizeBits()/8, "raw"),
		}, nil
	case *types.AlgorithmDetails_AesCbc:
		name, err := cipherNameFor(ctx, op, req.GetAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		ciphertext, iv, err := encryptAESCBC(ctx, p.libctx, name, req.GetKeyMaterial(), req.GetPlaintext(), alg.AesCbc)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.EncryptResponse{
			Ciphertext: ciphertext,
			Output:     provider.BlockCipherOutput(iv, "raw"),
		}, nil
	case *types.AlgorithmDetails_AesCtr:
		name, err := cipherNameFor(ctx, op, req.GetAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		ciphertext, iv, err := encryptAESCTR(ctx, p.libctx, name, req.GetKeyMaterial(), req.GetPlaintext(), alg.AesCtr)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.EncryptResponse{
			Ciphertext: ciphertext,
			Output:     provider.BlockCipherOutput(iv, "raw"),
		}, nil
	case *types.AlgorithmDetails_Chacha20Poly1305:
		if _, err := cipherNameFor(ctx, op, req.GetAlgorithm()); err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		ciphertext, nonce, err := encryptChaCha20Poly1305(ctx, p.libctx, req.GetKeyMaterial(), req.GetPlaintext(), req.GetAeadParams().GetAad())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.EncryptResponse{
			Ciphertext: ciphertext,
			Output:     provider.AeadOutput(nonce, chaCha20Poly1305TagSizeBytes, "raw"),
		}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for encrypt: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// Decrypt dispatches to the algorithm-specific decrypt implementation. The
// IV comes from req.GetOutput() — the ProviderOutput the core extracted
// from the stored OperationMetadata that Encrypt originally produced.
func (p *Provider) Decrypt(ctx context.Context, req *providerpb.DecryptRequest) (*providerpb.DecryptResponse, error) {
	const op errors.Op = "openssl.(Provider).Decrypt"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}

	switch alg := req.GetAlgorithm().GetAlgorithm().(type) {
	case *types.AlgorithmDetails_AesGcm:
		name, err := cipherNameFor(ctx, op, req.GetAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		plaintext, err := decryptAESGCM(ctx, p.libctx, name, req.GetKeyMaterial(), req.GetCiphertext(),
			req.GetOutput().GetAeadOutput().GetNonce(), req.GetAeadParams().GetAad(), alg.AesGcm)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.DecryptResponse{Plaintext: plaintext, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_AesCbc:
		name, err := cipherNameFor(ctx, op, req.GetAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		plaintext, err := decryptAESCBC(ctx, p.libctx, name, req.GetKeyMaterial(), req.GetCiphertext(),
			req.GetOutput().GetBlockCipherOutput().GetIv(), alg.AesCbc)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.DecryptResponse{Plaintext: plaintext, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_AesCtr:
		name, err := cipherNameFor(ctx, op, req.GetAlgorithm())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		plaintext, err := decryptAESCTR(ctx, p.libctx, name, req.GetKeyMaterial(), req.GetCiphertext(),
			req.GetOutput().GetBlockCipherOutput().GetIv(), alg.AesCtr)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.DecryptResponse{Plaintext: plaintext, Output: provider.NoOutputUnencoded()}, nil
	case *types.AlgorithmDetails_Chacha20Poly1305:
		if _, err := cipherNameFor(ctx, op, req.GetAlgorithm()); err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		plaintext, err := decryptChaCha20Poly1305(ctx, p.libctx, req.GetKeyMaterial(), req.GetCiphertext(),
			req.GetOutput().GetAeadOutput().GetNonce(), req.GetAeadParams().GetAad())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return &providerpb.DecryptResponse{Plaintext: plaintext, Output: provider.NoOutputUnencoded()}, nil
	default:
		return nil, errors.New(ctx, op, errors.CodeNotImplemented,
			fmt.Sprintf("unsupported algorithm for decrypt: %T", req.GetAlgorithm().GetAlgorithm()))
	}
}

// DestroyKey is a no-op for the stateless openssl provider, matching
// software.Provider.DestroyKey: the orchestrator manages key lifecycle, and
// this provider holds no internal state to release beyond the *ossl.Key
// every operation already closes for itself.
func (p *Provider) DestroyKey(_ context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	return &providerpb.DestroyKeyResponse{}, nil
}

// ExportPublicKey is not yet implemented.
func (p *Provider) ExportPublicKey(ctx context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	const op errors.Op = "openssl.(Provider).ExportPublicKey"
	return nil, errors.New(ctx, op, errors.CodeNotImplemented, "ExportPublicKey not yet implemented")
}

// Compile-time assertion: Provider implements provider.Backend.
var _ provider.Backend = (*Provider)(nil)

// Compile-time assertion: Provider implements provider.Signer.
var _ provider.Signer = (*Provider)(nil)

// Compile-time assertion: Provider implements provider.Cipher.
var _ provider.Cipher = (*Provider)(nil)

// Compile-time assertion: Provider implements AlgorithmCapabilityProvider.
var _ provider.AlgorithmCapabilityProvider = (*Provider)(nil)

// Compile-time assertion: Provider implements ImplementationDescriber.
var _ provider.ImplementationDescriber = (*Provider)(nil)
