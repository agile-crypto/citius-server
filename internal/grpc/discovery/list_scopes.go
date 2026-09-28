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
// A template scope this server cannot parse is skipped, as CreateKey's
// selection would skip it.
func (h *AlgorithmDiscoveryHandler) ListScopes(ctx context.Context, _ *servicespb.ListScopesRequest) (*servicespb.ListScopesResponse, error) {
	const op = algorithmDiscoveryHandlerOp + ".ListScopes"
	reg, err := h.templates(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}

	offered := offeredScopes(ctx, reg.List(ctx))

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
func offeredScopes(ctx context.Context, templates []*template.Template) map[core.Scope][]typespb.CryptoOperation {
	offered := map[core.Scope][]typespb.CryptoOperation{}
	for _, t := range templates {
		if t == nil {
			continue
		}
		for _, sc := range t.GetScopedCapabilities() {
			if sc.GetScope() == nil {
				continue
			}
			spec, err := core.ScopeSpecificationFromProto(ctx, sc.GetScope())
			if err != nil || !spec.Scope.IsValid() {
				continue
			}
			ops := offered[spec.Scope]
			for _, o := range sc.GetOperations() {
				if !slices.Contains(ops, o) {
					ops = append(ops, o)
				}
			}
			offered[spec.Scope] = ops
		}
	}
	return offered
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
