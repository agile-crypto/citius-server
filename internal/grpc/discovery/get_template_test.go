package discogrpc_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetTemplate(t *testing.T) {
	h, _ := newDiscovery(t)
	ctx := context.Background()

	resp, err := h.GetTemplate(ctx, &servicespb.GetTemplateRequest{TemplateId: "ml-dsa-65"})
	require.NoError(t, err)
	require.Equal(t, "ml-dsa-65", resp.GetTemplate().GetTemplateId())

	_, err = h.GetTemplate(ctx, &servicespb.GetTemplateRequest{TemplateId: "rot13"})
	require.Equal(t, codes.NotFound, status.Code(err))

	_, err = h.GetTemplate(ctx, &servicespb.GetTemplateRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
