package discogrpc_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/template"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	discogrpc "github.com/agile-crypto/citius-server/internal/grpc/discovery"
)

// fakeTemplates is a fixed template.Registry; only Get and List are served.
type fakeTemplates struct{ list []*template.Template }

func (f *fakeTemplates) Register(context.Context, *template.Template) error {
	panic("fakeTemplates.Register: not used")
}

func (f *fakeTemplates) Get(ctx context.Context, id string) (*template.Template, error) {
	for _, t := range f.list {
		if t.TemplateID() == id {
			return t, nil
		}
	}
	return nil, engerr.New(ctx, "fake.Get", engerr.CodeTemplateNotFound, "template not found: %s", id)
}

func (f *fakeTemplates) List(context.Context) []*template.Template { return f.list }

func (f *fakeTemplates) Select(context.Context, *core.ScopeSpecification, template.CandidateSet) (*template.Template, error) {
	panic("fakeTemplates.Select: not used")
}

func scopeProto(t *testing.T, s core.Scope) *typespb.ScopeSpecification {
	t.Helper()
	spec, err := core.NewScopeSpecification(context.Background(), s, nil, nil, nil)
	require.NoError(t, err)
	p, err := spec.ToProto(context.Background())
	require.NoError(t, err)
	return p
}

func tmpl(t *testing.T, id string, s core.Scope, st typespb.TemplateStatus, standards []string, ops ...typespb.CryptoOperation) *template.Template {
	t.Helper()
	return template.NewTemplate(&typespb.TemplateInfo{
		TemplateId: id,
		Status:     st,
		Standards:  standards,
		ScopedCapabilities: []*typespb.ScopedCapabilities{
			{Scope: scopeProto(t, s), Operations: ops},
		},
	})
}

func newDiscovery(t *testing.T) (*discogrpc.AlgorithmDiscoveryHandler, *fakeTemplates) {
	t.Helper()
	reg := &fakeTemplates{list: []*template.Template{
		tmpl(t, "ml-dsa-65", core.ScopeSignatureStandard, typespb.TemplateStatus_TEMPLATE_STATUS_EXPERIMENTAL, []string{"FIPS 204"},
			typespb.CryptoOperation_CRYPTO_OPERATION_SIGN, typespb.CryptoOperation_CRYPTO_OPERATION_VERIFY),
		tmpl(t, "aes-256-gcm", core.ScopeAeadStandard, typespb.TemplateStatus_TEMPLATE_STATUS_ACTIVE, []string{"NIST SP 800-38D", "FIPS 197"},
			typespb.CryptoOperation_CRYPTO_OPERATION_ENCRYPT, typespb.CryptoOperation_CRYPTO_OPERATION_DECRYPT),
		tmpl(t, "chacha20-poly1305", core.ScopeAeadStandard, typespb.TemplateStatus_TEMPLATE_STATUS_ACCEPTABLE, []string{"RFC 8439"},
			typespb.CryptoOperation_CRYPTO_OPERATION_DECRYPT, typespb.CryptoOperation_CRYPTO_OPERATION_ENCRYPT),
	}}
	h, err := discogrpc.New(context.Background(), func(context.Context) (template.Registry, error) { return reg, nil })
	require.NoError(t, err)
	return h, reg
}

func templateIDs(resp *servicespb.ListTemplatesResponse) []string {
	ids := make([]string, 0, len(resp.GetTemplates()))
	for _, t := range resp.GetTemplates() {
		ids = append(ids, t.GetTemplateId())
	}
	return ids
}

func TestListTemplates_Filters(t *testing.T) {
	h, _ := newDiscovery(t)
	ctx := context.Background()

	for name, tc := range map[string]struct {
		req  *servicespb.ListTemplatesRequest
		want []string
	}{
		"everything, by ID": {req: &servicespb.ListTemplatesRequest{}, want: []string{"aes-256-gcm", "chacha20-poly1305", "ml-dsa-65"}},
		"by scope":          {req: &servicespb.ListTemplatesRequest{ScopeSpec: scopeProto(t, core.ScopeAeadStandard)}, want: []string{"aes-256-gcm", "chacha20-poly1305"}},
		"by status": {req: &servicespb.ListTemplatesRequest{AllowedStatuses: []typespb.TemplateStatus{
			typespb.TemplateStatus_TEMPLATE_STATUS_ACTIVE, typespb.TemplateStatus_TEMPLATE_STATUS_EXPERIMENTAL,
		}}, want: []string{"aes-256-gcm", "ml-dsa-65"}},
		"by every standard": {req: &servicespb.ListTemplatesRequest{RequiredStandards: []string{"FIPS 197", "NIST SP 800-38D"}}, want: []string{"aes-256-gcm"}},
		"no match":          {req: &servicespb.ListTemplatesRequest{RequiredStandards: []string{"FIPS 197", "RFC 8439"}}, want: []string{}},
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := h.ListTemplates(ctx, tc.req)
			require.NoError(t, err)
			require.Equal(t, tc.want, templateIDs(resp))
		})
	}
}

func TestListTemplates_Pages(t *testing.T) {
	h, _ := newDiscovery(t)
	ctx := context.Background()

	first, err := h.ListTemplates(ctx, &servicespb.ListTemplatesRequest{PageSize: 2})
	require.NoError(t, err)
	require.Equal(t, []string{"aes-256-gcm", "chacha20-poly1305"}, templateIDs(first))
	rest, err := h.ListTemplates(ctx, &servicespb.ListTemplatesRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	require.NoError(t, err)
	require.Equal(t, []string{"ml-dsa-65"}, templateIDs(rest))
	require.Empty(t, rest.GetNextPageToken())
}

func TestListTemplates_InvalidRequests(t *testing.T) {
	h, _ := newDiscovery(t)
	for name, req := range map[string]*servicespb.ListTemplatesRequest{
		"negative page_size": {PageSize: -1},
		"bad page_token":     {PageToken: "nope"},
		"empty scope_spec":   {ScopeSpec: &typespb.ScopeSpecification{}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.ListTemplates(context.Background(), req)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

// A response is a copy: editing it leaves the catalogue as it was.
func TestListTemplates_ReturnsCopies(t *testing.T) {
	h, reg := newDiscovery(t)
	resp, err := h.ListTemplates(context.Background(), &servicespb.ListTemplatesRequest{})
	require.NoError(t, err)
	resp.GetTemplates()[0].TemplateId = "tampered"
	require.NotEqual(t, "tampered", reg.list[1].TemplateID())
}
