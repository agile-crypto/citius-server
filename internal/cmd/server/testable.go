package server

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"

	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/service"
	cryptohandler "github.com/agile-crypto/citius-server/internal/grpc/crypto"
	keymgmthandler "github.com/agile-crypto/citius-server/internal/grpc/keymanagement"
	policyhandler "github.com/agile-crypto/citius-server/internal/grpc/policy"
	"github.com/agile-crypto/citius-server/internal/storage"
)

// TestableHandler wraps a Handler with access to a shared request-scoped
// storage and the underlying app.Service.  This enables tests to seed
// policies before exercising the gRPC methods.
//
// Exported for use from the _test package (server_test); not intended for
// production code.
type TestableHandler struct {
	CryptoHandler *cryptohandler.CryptoHandler
	KeysHandler   *keymgmthandler.KeyManagementHandler
	PolicyHandler *policyhandler.CryptoPolicyHandler

	store                storage.Storage
	keyOrchestratorFn    service.KeyOrchestratorFactory
	cryptoOrchestratorFn service.CryptoOrchestratorFactory
	policyEngineFn       policy.EngineFactory
}

// NewTestableServer is like NewServer but returns a TestableHandler that
// shares a single InmemStorage instance between the handler and the test's
// policy-seeding calls.  This ensures policies created by the test are
// visible to the handler's factory closures.
func NewTestableServer(ctx context.Context, cfg Config) (*TestableHandler, error) {
	const op engerr.Op = "server.NewTestableServer"
	// Both the handler's storageFactory and SeedPolicy use the SAME
	// InmemStorage so that policies seeded before an RPC are visible.
	sharedStore := &logical.InmemStorage{}

	fns, err := wireFactoriesWithStorage(ctx, cfg, sharedStore, op)
	if err != nil {
		return nil, err
	}
	cryptoHandler, err := cryptohandler.New(ctx, fns.Crypto, fns.AuthorizeKey)
	if err != nil {
		return nil, engerr.Wrap(ctx, op, err)
	}
	keysHandler, err := keymgmthandler.New(ctx, fns.Keys, fns.AuthorizeKey, fns.AuthorizePolicy)
	if err != nil {
		return nil, engerr.Wrap(ctx, op, err)
	}
	policyHandler, err := policyhandler.New(ctx, fns.Policy, fns.AuthorizePolicy)
	if err != nil {
		return nil, engerr.Wrap(ctx, op, err)
	}
	return &TestableHandler{
		CryptoHandler:        cryptoHandler,
		KeysHandler:          keysHandler,
		PolicyHandler:        policyHandler,
		keyOrchestratorFn:    fns.Keys,
		cryptoOrchestratorFn: fns.Crypto,
		policyEngineFn:       fns.Policy,
		store:                sharedStore,
	}, nil
}

// SeedPolicy creates a policy with the given name and JSON rules in the
// shared test storage, making it available to subsequent handler calls.
func (th *TestableHandler) SeedPolicy(ctx context.Context, name string, rulesJSON []byte) error {
	const op engerr.Op = "server.TestableHandler.SeedPolicy"
	engine, err := th.policyEngineFn(ctx)
	if err != nil {
		return engerr.Wrap(ctx, op, err)
	}
	p := policy.NewPolicy(core.NewID(core.PolicyPrefix), name, rulesJSON)
	if _, err := engine.CreatePolicy(ctx, p); err != nil {
		return engerr.Wrap(ctx, op, err)
	}
	return nil
}
