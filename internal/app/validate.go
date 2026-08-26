package app

import (
	"context"
	"fmt"

	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider"
	"github.com/agile-crypto/citius-server/internal/template"
)

// ValidateProviderCapabilities checks that every algorithm ID declared by a
// provider's SupportedAlgorithms() has a corresponding template in the
// template registry, and that the provider implements every Backend
// capability (Signer, Cipher, ...) that template's scoped_capabilities
// actually requires.
//
// This is an application-layer coordination function that bridges the
// provider and template bounded contexts - neither imports the other.
// It is called at provider registration time to catch configuration errors
// early (fail-fast) rather than at operation time when MatchForTemplate()
// silently fails, or - for the capability check - when a request-time type
// assertion in the orchestrator returns CodeNotImplemented. A provider that
// advertises a template but cannot serve it is a static misconfiguration,
// not something that should surface per-request.
//
// If the provider does not implement [provider.AlgorithmCapabilityProvider],
// validation is skipped - the provider doesn't declare specific algorithm
// support.
func ValidateProviderCapabilities(
	ctx context.Context,
	p provider.Backend,
	templateReg template.Registry,
) error {
	const op errors.Op = "app.ValidateProviderCapabilities"

	cap, ok := p.(provider.AlgorithmCapabilityProvider)
	if !ok {
		return nil
	}

	algorithms := cap.SupportedAlgorithms()
	if len(algorithms) == 0 {
		return nil
	}

	var unknown []string
	var missing []string
	for _, algID := range algorithms {
		tmpl, err := templateReg.Get(ctx, algID)
		if err != nil {
			unknown = append(unknown, algID)
			continue
		}
		missing = append(missing, missingCapabilitiesFor(p, algID, tmpl)...)
	}

	if len(unknown) > 0 {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("provider %q declares unknown algorithms: %v", p.Name(), unknown))
	}
	if len(missing) > 0 {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("provider %q does not implement capabilities required by its declared algorithms: %v", p.Name(), missing))
	}
	return nil
}

// missingCapabilitiesFor returns one "<algID> needs <capability>" entry for
// every capability tmpl's scoped_capabilities require that p does not
// implement.
func missingCapabilitiesFor(p provider.Backend, algID string, tmpl *template.Template) []string {
	var missing []string
	for _, c := range provider.RequiredCapabilities(tmpl.GetScopedCapabilities()) {
		if !provider.HasCapability(p, c) {
			missing = append(missing, fmt.Sprintf("%s needs %s", algID, c))
		}
	}
	return missing
}

// ValidateAllProviders validates every provider in the registry against the
// template registry. Call this at startup after loading templates and
// registering providers.
func ValidateAllProviders(
	ctx context.Context,
	providerReg provider.Registry,
	templateReg template.Registry,
) error {
	const op errors.Op = "app.ValidateAllProviders"

	for _, p := range providerReg.List(ctx) {
		if err := ValidateProviderCapabilities(ctx, p, templateReg); err != nil {
			return errors.Wrap(ctx, op, err)
		}
	}
	return nil
}
