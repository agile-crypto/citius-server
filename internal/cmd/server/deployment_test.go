package server_test

import (
	"context"
	"strings"
	"testing"

	"github.com/agile-crypto/citius-server/internal/cmd/server"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/policy"
	"github.com/agile-crypto/citius-server/internal/provider"
	"github.com/agile-crypto/citius-server/internal/service"
	"github.com/agile-crypto/citius-server/internal/template"

	"google.golang.org/grpc"
)

// fullSet is a FactorySet with every capability wired to a factory that is
// never invoked: Validate and RegisterAll only check for presence and build
// handlers, so the factories need not produce anything.
func fullSet() server.FactorySet {
	return server.FactorySet{
		Keys:      func(context.Context) (service.KeyOrchestrator, error) { return nil, nil },
		Crypto:    func(context.Context) (service.CryptoOrchestrator, error) { return nil, nil },
		Policy:    func(context.Context) (policy.Engine, error) { return nil, nil },
		Instances: func(context.Context) (provider.InstanceManager, error) { return nil, nil },
		Templates: func(context.Context) (template.Registry, error) { return nil, nil },
		Catalog:   func(context.Context) (provider.Registry, error) { return nil, nil },

		AuthorizeKey:    server.AllowAllKeyNames(),
		AuthorizePolicy: server.AllowAllPolicyNames(),
	}
}

// recordingRegistrar captures which services were registered, so the tests can
// assert that a deployment exposes exactly what it selected — no more.
type recordingRegistrar struct{ names []string }

func (r *recordingRegistrar) RegisterService(desc *grpc.ServiceDesc, _ any) {
	r.names = append(r.names, desc.ServiceName)
}

func TestServices_Validate_NoServiceEnabled(t *testing.T) {
	err := server.Services{}.Validate(fullSet())
	if err == nil {
		t.Fatal("expected an error when no service is enabled")
	}
	var e *engerr.Error
	if !engerr.As(err, &e) || e.Code != engerr.CodeInvalidArgument {
		t.Errorf("code: got %v want CodeInvalidArgument", err)
	}
}

func TestServices_Validate_FullSetIsValid(t *testing.T) {
	all := server.Services{
		KeyManagement: true, Crypto: true, CryptoPolicy: true, Discovery: true,
		Provider: true, KeyEstablishment: true, Streaming: true,
	}
	if err := all.Validate(fullSet()); err != nil {
		t.Fatalf("full set should validate: %v", err)
	}
}

// A service enabled without its factory must fail at startup, naming both the
// service and what it is missing — not on the first RPC.
func TestServices_Validate_MissingDependencies(t *testing.T) {
	cases := []struct {
		name    string
		svcs    server.Services
		strip   func(*server.FactorySet)
		wantSub string
	}{
		{"key management without orchestrator", server.Services{KeyManagement: true},
			func(f *server.FactorySet) { f.Keys = nil }, "key orchestrator factory"},
		{"key management without key check", server.Services{KeyManagement: true},
			func(f *server.FactorySet) { f.AuthorizeKey = nil }, "key authorization check"},
		{"crypto without orchestrator", server.Services{Crypto: true},
			func(f *server.FactorySet) { f.Crypto = nil }, "crypto orchestrator factory"},
		{"policy without engine", server.Services{CryptoPolicy: true},
			func(f *server.FactorySet) { f.Policy = nil }, "policy engine factory"},
		{"policy without policy check", server.Services{CryptoPolicy: true},
			func(f *server.FactorySet) { f.AuthorizePolicy = nil }, "policy authorization check"},
		{"discovery without templates", server.Services{Discovery: true},
			func(f *server.FactorySet) { f.Templates = nil }, "template registry factory"},
		{"provider without catalogue", server.Services{Provider: true},
			func(f *server.FactorySet) { f.Catalog = nil }, "provider registry factory"},
		{"provider without instances", server.Services{Provider: true},
			func(f *server.FactorySet) { f.Instances = nil }, "provider instance manager factory"},
		{"key establishment without keys", server.Services{KeyEstablishment: true},
			func(f *server.FactorySet) { f.Keys = nil }, "key orchestrator factory"},
		{"streaming without crypto", server.Services{Streaming: true},
			func(f *server.FactorySet) { f.Crypto = nil }, "crypto orchestrator factory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fullSet()
			tc.strip(&f)
			err := tc.svcs.Validate(f)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("message %q does not mention %q", err.Error(), tc.wantSub)
			}
			// Negative control: the same selection validates once restored.
			if err := tc.svcs.Validate(fullSet()); err != nil {
				t.Errorf("unstripped set should validate: %v", err)
			}
		})
	}
}

// A capability a deployment does not serve is not required, which is the whole
// point of the subset design.
func TestServices_Validate_PolicyOnlyNeedsOnlyPolicy(t *testing.T) {
	f := server.FactorySet{
		Policy:          func(context.Context) (policy.Engine, error) { return nil, nil },
		AuthorizePolicy: server.AllowAllPolicyNames(),
	}
	if err := (server.Services{CryptoPolicy: true}).Validate(f); err != nil {
		t.Fatalf("a policy-only deployment must validate with only policy wired: %v", err)
	}
}

func TestRegisterAll_RegistersOnlySelectedServices(t *testing.T) {
	reg := &recordingRegistrar{}
	svcs := server.Services{CryptoPolicy: true, Discovery: true}

	if err := server.RegisterAll(context.Background(), reg, svcs, fullSet()); err != nil {
		t.Fatalf("RegisterAll: %v", err)
	}

	want := map[string]bool{
		"caas.crypto.v1.CryptoPolicyService":       true,
		"caas.crypto.v1.AlgorithmDiscoveryService": true,
	}
	if len(reg.names) != len(want) {
		t.Fatalf("registered %v, want exactly %d services", reg.names, len(want))
	}
	for _, n := range reg.names {
		if !want[n] {
			t.Errorf("unexpected service registered: %s", n)
		}
	}
}

func TestRegisterAll_AllServices(t *testing.T) {
	reg := &recordingRegistrar{}
	all := server.Services{
		KeyManagement: true, Crypto: true, CryptoPolicy: true, Discovery: true,
		Provider: true, KeyEstablishment: true, Streaming: true,
	}
	if err := server.RegisterAll(context.Background(), reg, all, fullSet()); err != nil {
		t.Fatalf("RegisterAll: %v", err)
	}
	if len(reg.names) != 7 {
		t.Errorf("registered %d services (%v), want 7", len(reg.names), reg.names)
	}
}

// RegisterAll validates first: an invalid deployment registers nothing rather
// than half a server.
func TestRegisterAll_InvalidDeploymentRegistersNothing(t *testing.T) {
	reg := &recordingRegistrar{}
	f := fullSet()
	f.Policy = nil

	err := server.RegisterAll(context.Background(), reg, server.Services{CryptoPolicy: true}, f)
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(reg.names) != 0 {
		t.Errorf("registered %v, want nothing", reg.names)
	}
}

// ============================================================================
// NewFactorySet
// ============================================================================

// allServices is every service this server can expose.
func allServices() server.Services {
	return server.Services{
		KeyManagement: true, Crypto: true, CryptoPolicy: true, Discovery: true,
		Provider: true, KeyEstablishment: true, Streaming: true,
	}
}

// The set NewFactorySet builds must satisfy every service, or the composition
// root cannot register the server it is meant to describe.
func TestNewFactorySet_ValidatesForAllServices(t *testing.T) {
	ctx := context.Background()
	f, err := server.WireFactorySet(ctx, server.Config{CatalogPath: catalogPath()})
	if err != nil {
		t.Fatalf("NewFactorySet: %v", err)
	}
	if err := allServices().Validate(f); err != nil {
		t.Fatalf("the full factory set must validate for every service: %v", err)
	}

	reg := &recordingRegistrar{}
	if err := server.RegisterAll(ctx, reg, allServices(), f); err != nil {
		t.Fatalf("RegisterAll: %v", err)
	}
	if len(reg.names) != 7 {
		t.Errorf("registered %d services (%v), want 7", len(reg.names), reg.names)
	}
}

// The factories must actually build their subsystems — a set that validates but
// cannot produce an orchestrator would fail on the first RPC instead.
func TestNewFactorySet_FactoriesBuild(t *testing.T) {
	ctx := context.Background()
	f, err := server.WireFactorySet(ctx, server.Config{CatalogPath: catalogPath()})
	if err != nil {
		t.Fatalf("NewFactorySet: %v", err)
	}

	if keys, err := f.Keys(ctx); err != nil || keys == nil {
		t.Errorf("Keys: got (%v, %v), want a key orchestrator", keys, err)
	}
	if ops, err := f.Crypto(ctx); err != nil || ops == nil {
		t.Errorf("Crypto: got (%v, %v), want a crypto orchestrator", ops, err)
	}
	if engine, err := f.Policy(ctx); err != nil || engine == nil {
		t.Errorf("Policy: got (%v, %v), want a policy engine", engine, err)
	}
	if inst, err := f.Instances(ctx); err != nil || inst == nil {
		t.Errorf("Instances: got (%v, %v), want an instance manager", inst, err)
	}
	if reg, err := f.Templates(ctx); err != nil || reg == nil {
		t.Errorf("Templates: got (%v, %v), want a template registry", reg, err)
	}
	if reg, err := f.Catalog(ctx); err != nil || reg == nil {
		t.Errorf("Catalog: got (%v, %v), want a provider registry", reg, err)
	}
}

// The store is shared across requests, so state written through one factory is
// visible through the next — the property NewServer's shared store exists for,
// and the one a per-request store would silently break.
func TestNewFactorySet_SharesStateAcrossRequests(t *testing.T) {
	ctx := context.Background()
	f, err := server.WireFactorySet(ctx, server.Config{CatalogPath: catalogPath()})
	if err != nil {
		t.Fatalf("NewFactorySet: %v", err)
	}

	writer, err := f.Policy(ctx)
	if err != nil {
		t.Fatalf("Policy (write): %v", err)
	}
	if _, err = writer.CreatePolicy(ctx, policy.NewPolicy("p1", "p1", []byte(`{"version":"1"}`))); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	// A second request builds a fresh engine over the same store.
	reader, err := f.Policy(ctx)
	if err != nil {
		t.Fatalf("Policy (read): %v", err)
	}
	got, err := reader.GetPolicy(ctx, "p1")
	if err != nil {
		t.Fatalf("GetPolicy from a later request: %v", err)
	}
	if got.Name() != "p1" {
		t.Errorf("name: got %q want p1", got.Name())
	}
}
