package providergrpc

import (
	"context"
	"slices"
	"strings"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"

	"github.com/agile-crypto/citius-server/internal/grpc/paging"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
)

// A provider is the Type() its instances report: openssl covers both the
// openssl and openssl-fips instances. Its template support is the union of
// what its instances advertise, each entry naming the instances that serve
// that template; implementation properties are per instance and are
// reported on the instances, not here.

// ListProviders handles the ListProviders RPC.
//
// Providers are ordered by ID. template_id keeps the providers with an
// instance that advertises it; requirements keeps the providers with an
// instance that meets every hard requirement. Both filters must hold on the
// same instance.
func (h *ProviderHandler) ListProviders(ctx context.Context, req *servicespb.ListProvidersRequest) (*servicespb.ListProvidersResponse, error) {
	const op = providerHandlerOp + ".ListProviders"

	required, err := core.ProviderRequirementsFromProto(ctx, req.GetRequirements())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err, engerr.WithMessage("invalid requirements")))
	}
	reg, err := h.providers(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}

	byType := instancesByType(registered(ctx, reg))
	ids := make([]string, 0, len(byType))
	for id, instances := range byType {
		if slices.ContainsFunc(instances, func(b provider.Backend) bool {
			return provider.Meets(b, required) && (req.GetTemplateId() == "" || advertises(b, req.GetTemplateId()))
		}) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)

	start, end, next, err := paging.Window(len(ids), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, op, engerr.CodeInvalidArgument, err.Error()))
	}
	resp := &servicespb.ListProvidersResponse{
		Providers:     make([]*typespb.ProviderInfo, 0, end-start),
		NextPageToken: next,
	}
	for _, id := range ids[start:end] {
		resp.Providers = append(resp.Providers, providerInfo(id, byType[id]))
	}
	return resp, nil
}

// GetProvider handles the GetProvider RPC.
func (h *ProviderHandler) GetProvider(ctx context.Context, req *servicespb.GetProviderRequest) (*servicespb.GetProviderResponse, error) {
	const op = providerHandlerOp + ".GetProvider"
	if req.GetProviderId() == "" {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, op, engerr.CodeInvalidArgument, "provider_id is required"))
	}
	reg, err := h.providers(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}
	instances := instancesByType(registered(ctx, reg))[req.GetProviderId()]
	if len(instances) == 0 {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, op, engerr.CodeProviderNotFound,
			"provider not found: %s", req.GetProviderId()))
	}
	return &servicespb.GetProviderResponse{Provider: providerInfo(req.GetProviderId(), instances)}, nil
}

// instancesByType groups backends by the provider type they report, keeping
// their order within each group.
func instancesByType(backends []provider.Backend) map[string][]provider.Backend {
	out := map[string][]provider.Backend{}
	for _, b := range backends {
		out[b.Type()] = append(out[b.Type()], b)
	}
	return out
}

// providerInfo describes provider id from its instances.
func providerInfo(id string, instances []provider.Backend) *typespb.ProviderInfo {
	servedBy := map[string][]string{}
	for _, b := range instances {
		sp, ok := b.(provider.AlgorithmCapabilityProvider)
		if !ok {
			continue
		}
		for _, t := range sp.SupportedAlgorithms() {
			if !slices.Contains(servedBy[t], b.Name()) {
				servedBy[t] = append(servedBy[t], b.Name())
			}
		}
	}
	templates := make([]string, 0, len(servedBy))
	for t := range servedBy {
		templates = append(templates, t)
	}
	slices.Sort(templates)

	info := &typespb.ProviderInfo{
		ProviderId:      id,
		DisplayName:     id,
		TemplateSupport: make([]*typespb.ProviderTemplateSupport, 0, len(templates)),
	}
	for _, t := range templates {
		info.TemplateSupport = append(info.TemplateSupport, &typespb.ProviderTemplateSupport{
			TemplateId: t,
			Notes:      "instances: " + strings.Join(servedBy[t], ", "),
		})
	}
	return info
}
