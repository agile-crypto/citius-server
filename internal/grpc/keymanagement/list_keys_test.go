package keygrpc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/service"
	keygrpc "github.com/agile-crypto/citius-server/internal/grpc/keymanagement"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func listFixture() []*service.KeyMetadata {
	active := typespb.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE
	return []*service.KeyMetadata{
		{Name: "charlie", Provider: "openssl-fips", Policy: "p1", LifecycleState: active},
		{Name: "alpha", Provider: "software", Policy: "p1", LifecycleState: active},
		{Name: "secret", Provider: "software", Policy: "p2", LifecycleState: active},
		{Name: "bravo", Provider: "software", Policy: "p2", LifecycleState: typespb.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED},
	}
}

func wireList(t *testing.T, authKey func(context.Context, engerr.Op, string) error) *keygrpc.KeyManagementHandler {
	t.Helper()
	km := &mockKeyOrchestrator{listFn: func(context.Context) ([]*service.KeyMetadata, error) { return listFixture(), nil }}
	newKeys := service.KeyOrchestratorFactory(func(context.Context) (service.KeyOrchestrator, error) { return km, nil })
	allow := func(context.Context, engerr.Op, string) error { return nil }
	if authKey == nil {
		authKey = allow
	}
	h, err := keygrpc.New(context.Background(), newKeys, authKey, allow)
	require.NoError(t, err)
	return h
}

func names(resp *messagespb.ListKeysResponse) []string {
	out := make([]string, 0, len(resp.GetKeys()))
	for _, k := range resp.GetKeys() {
		out = append(out, k.GetName())
	}
	return out
}

func TestKeyManagementHandler_ListKeys_SortedAndFiltered(t *testing.T) {
	h := wireList(t, nil)
	ctx := context.Background()

	resp, err := h.ListKeys(ctx, &messagespb.ListKeysRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"alpha", "bravo", "charlie", "secret"}, names(resp))
	require.Empty(t, resp.GetNextPageToken())

	resp, err = h.ListKeys(ctx, &messagespb.ListKeysRequest{ProviderId: "software", Policy: "p2"})
	require.NoError(t, err)
	require.Equal(t, []string{"bravo", "secret"}, names(resp))

	resp, err = h.ListKeys(ctx, &messagespb.ListKeysRequest{LifecycleState: typespb.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED})
	require.NoError(t, err)
	require.Equal(t, []string{"bravo"}, names(resp))
}

func TestKeyManagementHandler_ListKeys_LeavesOutForbiddenKeys(t *testing.T) {
	h := wireList(t, func(ctx context.Context, op engerr.Op, name string) error {
		if name == "secret" {
			return engerr.New(ctx, op, engerr.CodePolicyViolation, "forbidden")
		}
		return nil
	})
	resp, err := h.ListKeys(context.Background(), &messagespb.ListKeysRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"alpha", "bravo", "charlie"}, names(resp))
}

func TestKeyManagementHandler_ListKeys_UnauthenticatedFails(t *testing.T) {
	h := wireList(t, func(ctx context.Context, op engerr.Op, _ string) error {
		return engerr.New(ctx, op, engerr.CodeUnauthenticated, "no identity")
	})
	_, err := h.ListKeys(context.Background(), &messagespb.ListKeysRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestKeyManagementHandler_ListKeys_Pages(t *testing.T) {
	h := wireList(t, nil)
	ctx := context.Background()

	var got []string
	req := &messagespb.ListKeysRequest{PageSize: 3}
	for pages := 0; ; pages++ {
		require.Less(t, pages, 3, "paging did not terminate")
		resp, err := h.ListKeys(ctx, req)
		require.NoError(t, err)
		got = append(got, names(resp)...)
		if resp.GetNextPageToken() == "" {
			break
		}
		req.PageToken = resp.GetNextPageToken()
	}
	require.Equal(t, []string{"alpha", "bravo", "charlie", "secret"}, got)
}

func TestKeyManagementHandler_ListKeys_InvalidRequests(t *testing.T) {
	h := wireList(t, nil)
	for name, req := range map[string]*messagespb.ListKeysRequest{
		"negative page_size": {PageSize: -1},
		"garbage token":      {PageToken: "x"},
		"negative token":     {PageToken: "-2"},
		"token past end":     {PageToken: "99"},
		"scope_spec filter":  {ScopeSpec: &typespb.ScopeSpecification{}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.ListKeys(context.Background(), req)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestKeyManagementHandler_ListKeys_StoreFailureIsReported(t *testing.T) {
	km := &mockKeyOrchestrator{listFn: func(ctx context.Context) ([]*service.KeyMetadata, error) {
		return nil, engerr.Wrap(ctx, "test", errors.New("disk on fire"))
	}}
	h := wireKeys(t, km)
	_, err := h.ListKeys(context.Background(), &messagespb.ListKeysRequest{})
	require.Equal(t, codes.Internal, status.Code(err))
}
