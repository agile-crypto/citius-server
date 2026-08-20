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

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
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
		keyAlg, _, kerr := keyAlgorithmFor(ctx, op, req.GetAlgorithm())
		if kerr != nil {
			return nil, errors.Wrap(ctx, op, kerr)
		}
		pubDER, privDER, err = generateRSAKey(ctx, p.libctx, keyAlg, alg.RsaPss.GetKeySizeBits())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		privEnc = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI
	case *types.AlgorithmDetails_RsaPkcs1V15:
		keyAlg, _, kerr := keyAlgorithmFor(ctx, op, req.GetAlgorithm())
		if kerr != nil {
			return nil, errors.Wrap(ctx, op, kerr)
		}
		pubDER, privDER, err = generateRSAKey(ctx, p.libctx, keyAlg, alg.RsaPkcs1V15.GetKeySizeBits())
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		privEnc = providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8
		pubEnc = providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_SPKI
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

// DestroyKey is not yet implemented.
func (p *Provider) DestroyKey(ctx context.Context, _ *providerpb.DestroyKeyRequest) (*providerpb.DestroyKeyResponse, error) {
	const op errors.Op = "openssl.(Provider).DestroyKey"
	return nil, errors.New(ctx, op, errors.CodeNotImplemented, "DestroyKey not yet implemented")
}

// ExportPublicKey is not yet implemented.
func (p *Provider) ExportPublicKey(ctx context.Context, _ *providerpb.ExportPublicKeyRequest) (*providerpb.ExportPublicKeyResponse, error) {
	const op errors.Op = "openssl.(Provider).ExportPublicKey"
	return nil, errors.New(ctx, op, errors.CodeNotImplemented, "ExportPublicKey not yet implemented")
}

// Compile-time assertion: Provider implements provider.Backend.
var _ provider.Backend = (*Provider)(nil)

// Compile-time assertion: Provider implements AlgorithmCapabilityProvider.
var _ provider.AlgorithmCapabilityProvider = (*Provider)(nil)
