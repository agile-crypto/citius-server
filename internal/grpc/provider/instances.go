package providergrpc

import (
	"context"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/provider"

	"github.com/agile-crypto/citius-server/internal/grpc/paging"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
)

// ListProviderInstances handles the ListProviderInstances RPC.
//
// Instances are ordered by ID. provider_id keeps the instances of that
// provider; requirements keeps those whose reported implementation meets
// every hard requirement (the check CreateKey applies). Every served
// instance is enabled, so enabled_only changes nothing.
func (h *ProviderHandler) ListProviderInstances(ctx context.Context, req *servicespb.ListProviderInstancesRequest) (*servicespb.ListProviderInstancesResponse, error) {
	const op = providerHandlerOp + ".ListProviderInstances"

	required, err := core.ProviderRequirementsFromProto(ctx, req.GetRequirements())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err, engerr.WithMessage("invalid requirements")))
	}
	reg, err := h.providers(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}

	matched := make([]provider.Backend, 0)
	for _, b := range registered(ctx, reg) {
		if p := req.GetProviderId(); p != "" && b.Type() != p {
			continue
		}
		if !provider.Meets(b, required) {
			continue
		}
		matched = append(matched, b)
	}

	start, end, next, err := paging.Window(len(matched), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, op, engerr.CodeInvalidArgument, err.Error()))
	}
	resp := &servicespb.ListProviderInstancesResponse{
		Instances:     make([]*typespb.ProviderInstance, 0, end-start),
		NextPageToken: next,
	}
	for _, b := range matched[start:end] {
		resp.Instances = append(resp.Instances, instanceInfo(b))
	}
	return resp, nil
}

// GetProviderInstance handles the GetProviderInstance RPC.
func (h *ProviderHandler) GetProviderInstance(ctx context.Context, req *servicespb.GetProviderInstanceRequest) (*servicespb.GetProviderInstanceResponse, error) {
	const op = providerHandlerOp + ".GetProviderInstance"
	if req.GetInstanceId() == "" {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, op, engerr.CodeInvalidArgument, "instance_id is required"))
	}
	reg, err := h.providers(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}
	b, err := reg.Get(ctx, req.GetInstanceId())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}
	return &servicespb.GetProviderInstanceResponse{Instance: instanceInfo(b)}, nil
}
