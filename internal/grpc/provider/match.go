package providergrpc

import (
	"context"
	"slices"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"

	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
)

// Match scores. Only the order they give matters to a client.
const (
	scorePreferred = 2 // meets every requirement and has a preferred property
	scoreMeets     = 1 // meets every requirement
)

// MatchProviders handles the MatchProviders RPC.
//
// It returns the instances that can hold a key of template_id (every
// instance when it is empty) and meet every hard requirement, best first, in
// the order CreateKey chooses: instances with a property the requirements
// prefer, then the rest, each in registration order. So the first match is
// the instance CreateKey would pick for the same template and requirements
// when no instance is named. An instance that advertises the template but
// misses a requirement is left out; compare with ListProviderInstances to
// see which requirement it missed. No instance is disabled, so
// include_disabled changes nothing.
func (h *ProviderHandler) MatchProviders(ctx context.Context, req *servicespb.MatchProvidersRequest) (*servicespb.MatchProvidersResponse, error) {
	const op = providerHandlerOp + ".MatchProviders"

	required, err := core.ProviderRequirementsFromProto(ctx, req.GetRequirements())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err, engerr.WithMessage("invalid requirements")))
	}
	reg, err := h.providers(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}

	var preferred, rest []*servicespb.MatchedProvider
	for _, b := range reg.List(ctx) {
		if b == nil || !provider.Meets(b, required) {
			continue
		}
		if id := req.GetTemplateId(); id != "" && !advertises(b, id) {
			continue
		}
		m := &servicespb.MatchedProvider{
			Instance:               instanceInfo(b),
			ResolvedImplementation: implementationOf(b),
			MatchScore:             scoreMeets,
		}
		if required.PreferHardwareAccelerated && m.GetResolvedImplementation().GetHardwareAccelerated() {
			m.MatchScore = scorePreferred
			preferred = append(preferred, m)
			continue
		}
		rest = append(rest, m)
	}
	return &servicespb.MatchProvidersResponse{Matches: append(preferred, rest...)}, nil
}

// advertises reports whether b declares support for templateID.
func advertises(b provider.Backend, templateID string) bool {
	sp, ok := b.(provider.AlgorithmCapabilityProvider)
	return ok && slices.Contains(sp.SupportedAlgorithms(), templateID)
}
