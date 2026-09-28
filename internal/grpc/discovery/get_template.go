package discogrpc

import (
	"context"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	engerr "github.com/agile-crypto/citius-core/errors"

	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
)

// GetTemplate handles the GetTemplate RPC.
func (h *AlgorithmDiscoveryHandler) GetTemplate(ctx context.Context, req *servicespb.GetTemplateRequest) (*servicespb.GetTemplateResponse, error) {
	const op = algorithmDiscoveryHandlerOp + ".GetTemplate"
	if req.GetTemplateId() == "" {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, op, engerr.CodeInvalidArgument, "template_id is required"))
	}
	reg, err := h.templates(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}
	t, err := reg.Get(ctx, req.GetTemplateId())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}
	if t == nil || t.Proto() == nil {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, op, engerr.CodeTemplateNotFound,
			"template not found: %s", req.GetTemplateId()))
	}
	return &servicespb.GetTemplateResponse{Template: templateInfo(t)}, nil
}
