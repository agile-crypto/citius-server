// Package openssl implements a provider.Backend backed by OpenSSL 3.5
// libcrypto via github.com/agile-crypto/ossl-go.
//
// Mode — default, FIPS, PKCS#11 — is a property of which *ossl.Context a
// Provider instance wraps, not a runtime flag: an isolated OSSL_LIB_CTX has
// its own provider set, default property query, and DRBG state, independent
// of every other context. New builds the default-mode context; FIPS and
// PKCS#11 variants are constructed the same way through options, each
// registered under its own provider.Registry name so the existing
// key-to-provider routing (KeyVersion.ProviderId) binds every later
// operation on a key back to the exact context that created it.
//
// This package compiles under CGO_ENABLED=0: ossl-go ships a no-cgo mirror
// that returns ossl.ErrUnavailable from every operation rather than failing
// to build. New's ossl.CheckVersion call surfaces that at construction time,
// so a nocgo build fails to construct this provider instead of registering
// one that silently errors on every call.
package openssl

import (
	"context"

	"github.com/agile-crypto/ossl-go/ossl"

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
}

// New constructs a Provider using an isolated OpenSSL library context.
//
// It fails loudly if the runtime libcrypto does not match the library this
// package was built against — see ossl.CheckVersion — because a mismatch
// does not fail any other way: algorithms from a newer OpenSSL release just
// fetch as unsupported, silently.
func New(ctx context.Context, opts ...Option) (*Provider, error) {
	const op errors.Op = "openssl.New"

	if err := ossl.CheckVersion(); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	cfg := &config{name: defaultName}
	for _, opt := range opts {
		opt(cfg)
	}

	libctx, err := ossl.NewContext()
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	return &Provider{name: cfg.name, libctx: libctx}, nil
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

// GenerateKey is not yet implemented — key generation lands incrementally
// per algorithm family. The request is still validated first, matching the
// validate-then-dispatch shape every later method here follows.
func (p *Provider) GenerateKey(ctx context.Context, req *providerpb.GenerateKeyRequest) (*providerpb.GenerateKeyResponse, error) {
	const op errors.Op = "openssl.(Provider).GenerateKey"

	if err := validateRequest(ctx, op, req); err != nil {
		return nil, err
	}
	return nil, errors.New(ctx, op, errors.CodeNotImplemented, "GenerateKey not yet implemented")
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
