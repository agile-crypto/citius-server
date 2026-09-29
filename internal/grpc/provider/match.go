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
	scorePreferred int32 = 2 // meets every requirement and has a preferred property
	scoreMeets     int32 = 1 // meets every requirement
)

// MatchProviders handles the MatchProviders RPC.
//
// It returns the instances that can hold a key of template_id and meet
// every hard requirement, best first. The judgement and the order are
// core's provider.Rank, the rule Registry.Match applies: instances with a
// property the requirements prefer, then the rest, each in registration
// order. So the first match is the instance CreateKey would pick for the
// same template and requirements when no instance is named and no crypto
// policy adds requirements: MatchProviders judges only the requirements in
// the request, never a policy's provider_requirements. An instance Rank
// finds ineligible is left out; the response has no field for why yet.
// template_id is required, as the proto says. No instance is disabled, so
// include_disabled changes nothing.
func (h *ProviderHandler) MatchProviders(ctx context.Context, req *servicespb.MatchProvidersRequest) (*servicespb.MatchProvidersResponse, error) {
	const op = providerHandlerOp + ".MatchProviders"

	if req.GetTemplateId() == "" {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, op, engerr.CodeInvalidArgument, "template_id is required"))
	}
	required, err := core.ProviderRequirementsFromProto(ctx, req.GetRequirements())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err, engerr.WithMessage("invalid requirements")))
	}
	reg, err := h.providers(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}

	ranked := provider.Rank(reg.List(ctx), provider.Requirements{
		TemplateID:     req.GetTemplateId(),
		Implementation: required,
	})
	resp := &servicespb.MatchProvidersResponse{Matches: make([]*servicespb.MatchedProvider, 0, len(ranked))}
	for _, c := range ranked {
		if !c.Eligible() {
			break // Rank puts every ineligible candidate last
		}
		score := scoreMeets
		if c.Preferred {
			score = scorePreferred
		}
		resp.Matches = append(resp.Matches, &servicespb.MatchedProvider{
			Instance:               instanceInfo(c.Backend),
			ResolvedImplementation: c.Implementation,
			MatchScore:             score,
		})
	}
	return resp, nil
}

// advertises reports whether b declares support for templateID.
func advertises(b provider.Backend, templateID string) bool {
	sp, ok := b.(provider.AlgorithmCapabilityProvider)
	return ok && slices.Contains(sp.SupportedAlgorithms(), templateID)
}
