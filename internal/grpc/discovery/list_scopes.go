package discogrpc

import (
	"context"
	"slices"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/template"

	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
)

// ListScopes handles the ListScopes RPC.
//
// It returns, in the scope enum's order, each scope at least one registered
// template offers, with the operations those templates allow under it. A
// scope no template offers cannot be used to create a key, so it is left out.
// A registered template whose scope this server cannot read is a fault of
// the catalogue, not of the request: it fails CreateKey's selection too
// (template.MatchesScope), so it is reported as Internal, not skipped.
func (h *AlgorithmDiscoveryHandler) ListScopes(ctx context.Context, _ *servicespb.ListScopesRequest) (*servicespb.ListScopesResponse, error) {
	const op = algorithmDiscoveryHandlerOp + ".ListScopes"
	reg, err := h.templates(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}

	offered, err := offeredScopes(ctx, reg.List(ctx))
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}

	resp := &servicespb.ListScopesResponse{Scopes: make([]*typespb.ScopeInfo, 0, len(offered))}
	for _, s := range core.ListScopes() {
		ops, ok := offered[s]
		if !ok {
			continue
		}
		info, ierr := scopeInfo(ctx, s, ops)
		if ierr != nil {
			return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, ierr))
		}
		resp.Scopes = append(resp.Scopes, info)
	}
	return resp, nil
}

// offeredScopes maps each scope the templates offer to the operations they
// allow under it, each operation once.
func offeredScopes(ctx context.Context, templates []*template.Template) (map[core.Scope][]typespb.CryptoOperation, error) {
	offered := map[core.Scope][]typespb.CryptoOperation{}
	for _, t := range templates {
		if t == nil {
			continue
		}
		for _, sc := range t.GetScopedCapabilities() {
			if sc.GetScope() == nil {
				continue
			}
			s, err := templateScope(ctx, t, sc.GetScope())
			if err != nil {
				return nil, err
			}
			ops := offered[s]
			for _, o := range sc.GetOperations() {
				if !slices.Contains(ops, o) {
					ops = append(ops, o)
				}
			}
			offered[s] = ops
		}
	}
	return offered, nil
}

// templateScope reads the scope of one of t's scoped capabilities. A scope
// that cannot be read, or is not one this server knows, is Internal: the
// catalogue is at fault, not the request.
func templateScope(ctx context.Context, t *template.Template, scope *typespb.ScopeSpecification) (core.Scope, error) {
	const op = algorithmDiscoveryHandlerOp + ".templateScope"
	spec, err := core.ScopeSpecificationFromProto(ctx, scope)
	if err != nil {
		unreadable := engerr.New(ctx, op, engerr.CodeInternal,
			"template %s has a scope this server cannot read", t.TemplateID())
		unreadable.Wrapped = err
		return core.ScopeUnknown, unreadable
	}
	if !spec.Scope.IsValid() {
		return core.ScopeUnknown, engerr.New(ctx, op, engerr.CodeInternal,
			"template %s has an unknown scope", t.TemplateID())
	}
	return spec.Scope, nil
}

// scopeInfo describes scope s with the operations templates offer under it,
// in enum order.
func scopeInfo(ctx context.Context, s core.Scope, ops []typespb.CryptoOperation) (*typespb.ScopeInfo, error) {
	spec, err := core.NewScopeSpecification(ctx, s, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	specProto, err := spec.ToProto(ctx)
	if err != nil {
		return nil, err
	}
	sorted := slices.Clone(ops)
	slices.Sort(sorted)
	return &typespb.ScopeInfo{
		Specification:       specProto,
		Name:                s.String(),
		SupportedOperations: sorted,
	}, nil
}
