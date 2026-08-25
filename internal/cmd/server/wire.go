// Package server wires the production dependency graph.
//
// The single exported function, NewServer, assembles all core subsystems into
// a [grpchandler.Handler] ready for gRPC registration.
// All constructors are called here, not in main.go (keeps main thin).
// Every error is returned, never panicked - callers decide what to do.
// The Handler is safe for concurrent use after construction.
package server

import (
	"context"
	"log"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/agile-crypto/citius-server/internal/app"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
	grpchandler "github.com/agile-crypto/citius-server/internal/grpc"
	"github.com/agile-crypto/citius-server/internal/key"
	"github.com/agile-crypto/citius-server/internal/policy"
	"github.com/agile-crypto/citius-server/internal/provider"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
	"github.com/agile-crypto/citius-server/internal/service"
	"github.com/agile-crypto/citius-server/internal/storage"
	"github.com/agile-crypto/citius-server/internal/template"
)

// Config carries the small number of knobs for NewServer.
// All fields are optional — zero values select sensible defaults.
type Config struct {
	// CatalogPath is the path to the proto-JSON standard_algorithms.json file.
	// When empty, NewServer does not load a catalog (useful for testing).
	CatalogPath string

	// FIPSConfigPath is an OpenSSL config that `.include`s fipsmodule.cnf and
	// activates the fips provider (see openssl.WithFIPS's doc comment for the
	// exact shape required). When set, a second "openssl-fips" provider
	// instance is registered alongside the default-mode "openssl" one. When
	// empty, no FIPS instance is registered — FIPS is optional infrastructure
	// most deployments and most CI machines do not have installed.
	FIPSConfigPath string
}

// NewServer assembles the full dependency graph and returns a ready-to-use
// [grpchandler.Handler].
func NewServer(ctx context.Context, cfg Config) (*grpchandler.Handler, error) {
	// Template registry + catalog
	bootstrapStorage := &logical.InmemStorage{}
	templateReg, err := buildTemplateRegistry(ctx, bootstrapStorage, cfg.CatalogPath)
	if err != nil {
		return nil, err
	}

	// Provider registry + validation
	providerReg, err := buildProviderRegistry(ctx, templateReg, cfg.FIPSConfigPath)
	if err != nil {
		return nil, err
	}

	// app.Service
	//
	// Use a shared in-memory store across both bootstrap (templates) and
	// the per-request scope so that policies/keys created via one RPC are
	// visible to subsequent RPCs. Without this, every getScope() call
	// would receive a fresh empty store and policies would vanish
	// between CreateCryptoPolicy and CreateKey.
	sharedStore := &logical.InmemStorage{}
	svc, err := buildAppService(ctx, templateReg, providerReg, sharedStore)
	if err != nil {
		return nil, err
	}

	// Adapter => Handler
	gateway := &appServiceAdapter{svc: svc}
	storageFactory := func() storage.Storage { return sharedStore }

	return grpchandler.New(gateway, storageFactory), nil
}

// ============================================================================
// Shared bootstrap helpers (used by both NewServer and NewTestableServer)
// ============================================================================

// buildTemplateRegistry creates a VaultRegistry and optionally loads the
// standard algorithm catalog from disk.
func buildTemplateRegistry(
	ctx context.Context,
	bootstrapStorage *logical.InmemStorage,
	catalogPath string,
) (template.Registry, error) {
	const op engerr.Op = "server.buildTemplateRegistry"
	reg, err := template.NewVaultRegistry(ctx, bootstrapStorage)
	if err != nil {
		return nil, engerr.Wrap(ctx, op, err)
	}
	if catalogPath != "" {
		if err := template.LoadStandardCatalog(ctx, catalogPath, reg); err != nil {
			return nil, engerr.Wrap(ctx, op, err)
		}
	}
	return reg, nil
}

// buildProviderRegistry creates a provider.Registry, registers the
// software and openssl providers (plus an openssl-fips instance when
// fipsConfigPath is configured), and validates capabilities against the
// template registry.
func buildProviderRegistry(
	ctx context.Context,
	templateReg template.Registry,
	fipsConfigPath string,
) (provider.Registry, error) {
	const op engerr.Op = "server.buildProviderRegistry"
	providerReg := provider.NewRegistry()
	if err := providerReg.Register(ctx, software.New()); err != nil {
		return nil, engerr.Wrap(ctx, op, err)
	}
	// openssl.New fails at construction time on a runtime that cannot back
	// it -- a nocgo build, or a libcrypto that doesn't match the OpenSSL 3.5
	// this package was built against (see the package's own doc comment) --
	// rather than registering a provider that would error on every call, so
	// this is deliberately fatal the same way the software registration is.
	osslProvider, err := openssl.New(ctx)
	if err != nil {
		return nil, engerr.Wrap(ctx, op, err)
	}
	if err := providerReg.Register(ctx, osslProvider); err != nil {
		return nil, engerr.Wrap(ctx, op, err)
	}
	registerFIPSProvider(ctx, providerReg, fipsConfigPath)
	if err := app.ValidateAllProviders(ctx, providerReg, templateReg); err != nil {
		return nil, engerr.Wrap(ctx, op, err)
	}
	return providerReg, nil
}

// registerFIPSProvider registers a second openssl instance restricted to
// the FIPS module, when fipsConfigPath is configured.
//
// Unlike the software/openssl registrations above, failure here is
// deliberately non-fatal: FIPS is optional infrastructure most deployments
// and most CI machines do not have installed, and requiring it would break
// a stock build. This is the one place in this file that logs instead of
// just returning an error -- there is no error-return channel for "skipped,
// not wrong" the way there is for the fatal registrations, and a silent
// skip would let an operator who genuinely configured FIPS not notice it
// never activated.
func registerFIPSProvider(ctx context.Context, providerReg provider.Registry, fipsConfigPath string) {
	if fipsConfigPath == "" {
		return
	}
	fipsProvider, err := openssl.New(ctx, openssl.WithName("openssl-fips"), openssl.WithFIPS(fipsConfigPath))
	if err != nil {
		log.Printf("openssl-fips: construction failed, continuing without a FIPS provider: %v", err)
		return
	}
	if err := providerReg.Register(ctx, fipsProvider); err != nil {
		log.Printf("openssl-fips: registration failed, continuing without a FIPS provider: %v", err)
		return
	}
	log.Printf("openssl-fips: FIPS provider registered (config: %s)", fipsConfigPath)
}

// buildAppService constructs an app.Service from the shared registries.
// The optional overrideStore, when non-nil, makes every factory closure use
// that fixed storage instead of its argument - this is used by
// NewTestableServer to share state between policy seeding and handler calls.
func buildAppService(
	ctx context.Context,
	templateReg template.Registry,
	providerReg provider.Registry,
	overrideStore ...storage.Storage,
) (*app.Service, error) {
	const op engerr.Op = "server.buildAppService"

	// When an override is provided, factories ignore their argument and use it.
	resolve := func(s storage.Storage) storage.Storage { return s }
	if len(overrideStore) > 0 && overrideStore[0] != nil {
		fixed := overrideStore[0]
		resolve = func(_ storage.Storage) storage.Storage { return fixed }
	}

	keyFactory := func(s storage.Storage) (service.KeyOrchestrator, error) {
		return buildKeyOrchestrator(ctx, resolve(s), templateReg, providerReg)
	}
	cryptoFactory := func(s storage.Storage) (service.CryptoOrchestrator, error) {
		return buildCryptoOrchestrator(ctx, resolve(s), templateReg, providerReg)
	}
	policyFactory := func(s storage.Storage) (policy.Engine, error) {
		return buildPolicyEngine(ctx, resolve(s))
	}
	instanceFactory := func(_ storage.Storage) (provider.InstanceManager, error) {
		return &noopInstanceManager{}, nil
	}

	svc, err := app.NewService(
		app.WithKeyOrchestratorFactory(keyFactory),
		app.WithCryptoOrchestratorFactory(cryptoFactory),
		app.WithPolicyEngineFactory(policyFactory),
		app.WithProviderInstanceManagerFactory(instanceFactory),
		app.WithTemplateRegistry(templateReg),
		app.WithProviderRegistry(providerReg),
	)
	if err != nil {
		return nil, engerr.Wrap(ctx, op, err)
	}
	return svc, nil
}

// ============================================================================
// Factory builders — same pattern as integration tests
// ============================================================================

func buildKeyOrchestrator(
	ctx context.Context, s storage.Storage,
	templateReg template.Registry, providerReg provider.Registry,
) (service.KeyOrchestrator, error) {
	repo, err := key.NewVaultRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	policyRepo, err := policy.NewVaultRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	pol, err := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
	if err != nil {
		return nil, err
	}
	return service.NewKeyOrchestrator(repo, templateReg, providerReg, pol)
}

func buildCryptoOrchestrator(
	ctx context.Context, s storage.Storage,
	templateReg template.Registry, providerReg provider.Registry,
) (service.CryptoOrchestrator, error) {
	repo, err := key.NewVaultRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	policyRepo, err := policy.NewVaultRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	pol, err := policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
	if err != nil {
		return nil, err
	}
	return service.NewCryptoOrchestrator(s, repo, pol, providerReg, templateReg)
}

func buildPolicyEngine(
	ctx context.Context, s storage.Storage,
) (policy.Engine, error) {
	policyRepo, err := policy.NewVaultRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	return policy.NewEnforcer(policyRepo, policy.NewSimpleRulesEvaluator())
}

// ============================================================================
// Adapters & stubs
// ============================================================================

// appServiceAdapter bridges *app.Service (concrete ForStorage returning
// *RequestScope) to grpchandler.ServiceGateway (interface returning
// ScopeGateway).  *app.RequestScope already satisfies ScopeGateway
// (it has Keys() and Crypto() methods), so the adapter just converts
// the return type.
type appServiceAdapter struct {
	svc *app.Service
}

func (a *appServiceAdapter) ForStorage(ctx context.Context, store storage.Storage) (grpchandler.ScopeGateway, error) {
	return a.svc.ForStorage(ctx, store)
}

// noopInstanceManager satisfies provider.InstanceManager.
// TODO: Provider instance management is not yet implemented and will be wired later
type noopInstanceManager struct{}

func (n *noopInstanceManager) Create(_ context.Context, pi *provider.Instance) (*provider.Instance, error) {
	return pi, nil
}

func (n *noopInstanceManager) Read(_ context.Context, _ string) (*provider.Instance, error) {
	return nil, nil
}

func (n *noopInstanceManager) List(_ context.Context) ([]*provider.Instance, error) {
	return nil, nil
}

func (n *noopInstanceManager) Delete(_ context.Context, _ string) error { return nil }
