package server

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/agile-crypto/citius-server/internal/core"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
	grpchandler "github.com/agile-crypto/citius-server/internal/grpc"
	"github.com/agile-crypto/citius-server/internal/policy"
	"github.com/agile-crypto/citius-server/internal/storage"
)

// TestableHandler wraps a Handler with access to a shared request-scoped
// storage and the underlying app.Service.  This enables tests to seed
// policies before exercising the gRPC methods.
//
// Exported for use from the _test package (server_test); not intended for
// production code.
type TestableHandler struct {
	Handler *grpchandler.Handler
	store   storage.Storage
	svc     *appServiceAdapter
}

// NewTestableServer is like NewServer but returns a TestableHandler that
// shares a single InmemStorage instance between the handler and the test's
// policy-seeding calls.  This ensures policies created by the test are
// visible to the handler's factory closures.
func NewTestableServer(ctx context.Context, cfg Config) (*TestableHandler, error) {
	bootstrapStorage := &logical.InmemStorage{}
	templateReg, err := buildTemplateRegistry(ctx, bootstrapStorage, cfg.CatalogPath)
	if err != nil {
		return nil, err
	}

	providerReg, err := buildProviderRegistry(ctx, templateReg)
	if err != nil {
		return nil, err
	}

	// Both the handler's storageFactory and SeedPolicy use the SAME
	// InmemStorage so that policies seeded before an RPC are visible.
	sharedStore := &logical.InmemStorage{}

	svc, err := buildAppService(ctx, templateReg, providerReg, sharedStore)
	if err != nil {
		return nil, err
	}

	gateway := &appServiceAdapter{svc: svc}
	storageFactory := func() storage.Storage { return sharedStore }
	handler := grpchandler.New(gateway, storageFactory)

	return &TestableHandler{
		Handler: handler,
		store:   sharedStore,
		svc:     gateway,
	}, nil
}

// SeedPolicy creates a policy with the given name and JSON rules in the
// shared test storage, making it available to subsequent handler calls.
func (th *TestableHandler) SeedPolicy(ctx context.Context, name string, rulesJSON []byte) error {
	const op engerr.Op = "server.TestableHandler.SeedPolicy"

	scope, err := th.svc.ForStorage(ctx, th.store)
	if err != nil {
		return engerr.Wrap(ctx, op, err)
	}

	// scope is a ScopeGateway — we need the policy engine.
	// *app.RequestScope satisfies ScopeGateway AND has a Policy() method,
	// but ScopeGateway itself doesn't expose Policy().
	// We use a type assertion to access the full RequestScope.
	type policyAccess interface {
		Policy() policy.Engine
	}
	pa, ok := scope.(policyAccess)
	if !ok {
		return engerr.New(ctx, op, engerr.CodeInternal, "scope does not implement policyAccess")
	}

	p := policy.NewPolicy(core.NewID(core.PolicyPrefix), name, rulesJSON)
	if _, err := pa.Policy().CreatePolicy(ctx, p); err != nil {
		return engerr.Wrap(ctx, op, err)
	}
	return nil
}
