package crypto_test

import (
	"context"
	"slices"
	"testing"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
)

// TestSmoke_Discovery_catalogAgreesWithCreateKey reads the real catalogue and
// provider registry: the AEAD template is listed under its scope, and the
// first instance MatchProviders ranks is the one CreateKey places a key on.
func TestSmoke_Discovery_catalogAgreesWithCreateKey(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)

	tmpl, err := h.DiscoveryHandler.GetTemplate(ctx, &servicespb.GetTemplateRequest{TemplateId: aeadTemplate})
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	scope := tmpl.GetTemplate().GetScopedCapabilities()[0].GetScope()

	listed, err := h.DiscoveryHandler.ListTemplates(ctx, &servicespb.ListTemplatesRequest{ScopeSpec: scope})
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if !slices.ContainsFunc(listed.GetTemplates(), func(ti *typespb.TemplateInfo) bool {
		return ti.GetTemplateId() == aeadTemplate
	}) {
		t.Errorf("%s is not listed under its own scope", aeadTemplate)
	}

	scopes, err := h.DiscoveryHandler.ListScopes(ctx, &servicespb.ListScopesRequest{})
	if err != nil {
		t.Fatalf("ListScopes: %v", err)
	}
	if len(scopes.GetScopes()) == 0 {
		t.Fatal("ListScopes returned nothing for the standard catalogue")
	}

	matches, err := h.ProviderHandler.MatchProviders(ctx, &servicespb.MatchProvidersRequest{TemplateId: aeadTemplate})
	if err != nil {
		t.Fatalf("MatchProviders: %v", err)
	}
	if len(matches.GetMatches()) == 0 {
		t.Fatalf("no provider matches %s", aeadTemplate)
	}
	pol := seedPolicy(t, ctx, h, "discovery", []string{aeadTemplate}, []string{"create_key", "read_key"})
	keyName := createAEADKey(t, ctx, h, "discovery-key", pol)
	read, err := h.KeysHandler.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: keyName})
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if got, want := read.GetKeyMetadata().GetProvider(), matches.GetMatches()[0].GetInstance().GetInstanceId(); got != want {
		t.Errorf("CreateKey placed the key on %s; MatchProviders ranked %s first", got, want)
	}

	instances, err := h.ProviderHandler.ListProviderInstances(ctx, &servicespb.ListProviderInstancesRequest{})
	if err != nil {
		t.Fatalf("ListProviderInstances: %v", err)
	}
	for _, m := range matches.GetMatches() {
		if !slices.ContainsFunc(instances.GetInstances(), func(i *typespb.ProviderInstance) bool {
			return i.GetInstanceId() == m.GetInstance().GetInstanceId()
		}) {
			t.Errorf("match %s is not a listed instance", m.GetInstance().GetInstanceId())
		}
	}
}
