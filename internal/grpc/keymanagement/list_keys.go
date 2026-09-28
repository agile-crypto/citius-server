package keygrpc

import (
	"context"
	"slices"
	"strings"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/service"
	"github.com/agile-crypto/citius-server/internal/grpc/paging"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
)

// ListKeys handles the ListKeys RPC.
//
// It returns the current version of every key the caller may read, ordered by
// name. A key the caller is forbidden to read is left out rather than failing
// the listing; any other authorization failure (an unauthenticated caller)
// fails it. provider_id, policy and lifecycle_state narrow the result when
// set; scope_spec filtering is not supported and is refused rather than
// ignored.
//
// Paging: page_size 0 returns every match. Otherwise the response holds at
// most page_size keys and, when more remain, a next_page_token to pass back
// as page_token. The token is opaque to clients.
func (h *KeyManagementHandler) ListKeys(ctx context.Context, req *messagespb.ListKeysRequest) (*messagespb.ListKeysResponse, error) {
	const listOp engerr.Op = keyManagementHandlerOp + ".ListKeys"

	if req.GetScopeSpec() != nil {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, listOp, engerr.CodeInvalidArgument,
			"filtering by scope_spec is not supported"))
	}

	keys, err := h.keys(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, listOp, err))
	}
	all, err := keys.ListKeys(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, listOp, err))
	}

	matched, err := h.visibleKeys(ctx, listOp, req, all)
	if err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	start, end, next, err := paging.Window(len(matched), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, listOp, engerr.CodeInvalidArgument, err.Error()))
	}

	resp := &messagespb.ListKeysResponse{Keys: make([]*messagespb.KeyMetadata, 0, end-start), NextPageToken: next}
	for _, md := range matched[start:end] {
		p, perr := md.ToProto(ctx)
		if perr != nil {
			return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, listOp, perr))
		}
		resp.Keys = append(resp.Keys, p)
	}
	return resp, nil
}

// visibleKeys keeps the keys that match the request's filters and that the
// caller may read, ordered by name. A forbidden key is dropped; any other
// authorization error is returned.
func (h *KeyManagementHandler) visibleKeys(ctx context.Context, op engerr.Op, req *messagespb.ListKeysRequest, all []*service.KeyMetadata) ([]*service.KeyMetadata, error) {
	matched := make([]*service.KeyMetadata, 0, len(all))
	for _, md := range all {
		if md == nil || !listFilterMatches(req, md) {
			continue
		}
		if err := h.authorizeKey(ctx, op, md.Name); err != nil {
			if engerr.IsPolicyViolation(err) {
				continue
			}
			return nil, err
		}
		matched = append(matched, md)
	}
	slices.SortFunc(matched, func(a, b *service.KeyMetadata) int { return strings.Compare(a.Name, b.Name) })
	return matched, nil
}

// listFilterMatches reports whether md satisfies the request's set filters.
func listFilterMatches(req *messagespb.ListKeysRequest, md *service.KeyMetadata) bool {
	if p := req.GetProviderId(); p != "" && p != md.Provider {
		return false
	}
	if p := req.GetPolicy(); p != "" && p != md.Policy {
		return false
	}
	if s := req.GetLifecycleState(); s != typespb.KeyLifecycleState_KEY_LIFECYCLE_STATE_UNSPECIFIED && s != md.LifecycleState {
		return false
	}
	return true
}
