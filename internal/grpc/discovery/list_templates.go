package discogrpc

import (
	"context"
	"slices"
	"strings"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/template"
	"google.golang.org/protobuf/proto"

	"github.com/agile-crypto/citius-server/internal/grpc/paging"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
)

// ListTemplates handles the ListTemplates RPC.
//
// Templates are ordered by ID. Each set filter narrows the result:
// scope_spec keeps the templates that offer a matching scope (the match
// CreateKey applies), allowed_statuses keeps the templates in one of those
// statuses, and required_standards keeps those that list every named
// standard. With no filter every registered template is returned, whatever
// its status.
func (h *AlgorithmDiscoveryHandler) ListTemplates(ctx context.Context, req *servicespb.ListTemplatesRequest) (*servicespb.ListTemplatesResponse, error) {
	const op = algorithmDiscoveryHandlerOp + ".ListTemplates"

	var want *core.ScopeSpecification
	if req.GetScopeSpec() != nil {
		spec, err := core.ScopeSpecificationFromProto(ctx, req.GetScopeSpec())
		if err != nil {
			return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err, engerr.WithMessage("invalid scope_spec")))
		}
		want = spec
	}

	reg, err := h.templates(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}
	all := reg.List(ctx)
	matched := make([]*template.Template, 0, len(all))
	for _, t := range all {
		ok, merr := templateMatches(ctx, req, want, t)
		if merr != nil {
			return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, merr))
		}
		if ok {
			matched = append(matched, t)
		}
	}
	slices.SortFunc(matched, func(a, b *template.Template) int { return strings.Compare(a.TemplateID(), b.TemplateID()) })

	start, end, next, err := paging.Window(len(matched), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, op, engerr.CodeInvalidArgument, err.Error()))
	}
	resp := &servicespb.ListTemplatesResponse{
		Templates:     make([]*typespb.TemplateInfo, 0, end-start),
		NextPageToken: next,
	}
	for _, t := range matched[start:end] {
		resp.Templates = append(resp.Templates, templateInfo(t))
	}
	return resp, nil
}

// templateMatches reports whether t passes every filter req sets; want is
// req's scope specification, already parsed.
func templateMatches(ctx context.Context, req *servicespb.ListTemplatesRequest, want *core.ScopeSpecification, t *template.Template) (bool, error) {
	if t == nil || t.Proto() == nil {
		return false, nil
	}
	info := t.Proto()
	if s := req.GetAllowedStatuses(); len(s) > 0 && !slices.Contains(s, info.GetStatus()) {
		return false, nil
	}
	for _, std := range req.GetRequiredStandards() {
		if !slices.Contains(info.GetStandards(), std) {
			return false, nil
		}
	}
	if want == nil {
		return true, nil
	}
	return template.MatchesScope(ctx, t, want)
}

// templateInfo returns a copy of t's catalogue entry, so a caller that edits
// a response (an in-process client can) never edits the registry.
func templateInfo(t *template.Template) *typespb.TemplateInfo {
	info, _ := proto.Clone(t.Proto()).(*typespb.TemplateInfo)
	return info
}
