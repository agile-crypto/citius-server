package openssl

import (
	"context"
	"sort"

	"github.com/agile-crypto/ossl-go/ossl"

	"github.com/agile-crypto/citius-server/internal/errors"
)

// catalog maps a template ID — matching the standard algorithm catalog's
// TemplateID values, the same contract software.SupportedAlgorithms
// documents — to the ossl.Capability New checks the instance's context
// against.
var catalog = map[string]ossl.Capability{}

// deriveAlgorithms filters table down to the entries libctx can actually
// perform, via ossl.Context.Supports — a structural check, cheap enough to
// run over the whole catalogue (the one exception, an EC curve, costs one
// ephemeral keygen the first time a context is asked and is memoised after).
//
// table is a parameter rather than this function always reading the
// package-level catalog so it stays a pure function: callers — New, and
// this package's tests — can run it against a synthetic table, independent
// of whatever this package currently advertises for real.
//
// The result is sorted so two instances built against the same context
// report algorithms in the same order — map iteration order is not
// something a caller (or a test asserting equality) should have to tolerate.
func deriveAlgorithms(libctx *ossl.Context, table map[string]ossl.Capability) []string {
	var out []string
	for id, cap := range table {
		if err := libctx.Supports(cap); err == nil {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// SupportedAlgorithms returns the algorithm IDs this instance's context
// actually supports — derived once at construction (see New), never
// hardcoded. This is what makes a FIPS- or PKCS#11-restricted instance
// advertise only what it can really do: every mode instance filters the
// same catalog table, and each one's own context decides what survives.
func (p *Provider) SupportedAlgorithms() []string {
	out := make([]string, len(p.algs))
	copy(out, p.algs)
	return out
}

// VerifyCapabilities proves every algorithm this instance advertises by
// actually performing it — ossl.Context.VerifyCapability against ephemeral
// material — rather than relying on the structural check SupportedAlgorithms
// is built on.
//
// This costs a key generation per algorithm — seconds for RSA-4096 — so it
// is opt-in: never called from New or a request path. Run it once during
// deployment validation to confirm a configuration works, not per request.
func (p *Provider) VerifyCapabilities(ctx context.Context) error {
	const op errors.Op = "openssl.(Provider).VerifyCapabilities"
	for _, id := range p.algs {
		if err := p.libctx.VerifyCapability(catalog[id]); err != nil {
			return errors.Wrap(ctx, op, err, errors.WithMessage("algorithm %q", id))
		}
	}
	return nil
}
