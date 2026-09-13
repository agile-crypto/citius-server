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

	engerr "github.com/agile-crypto/citius-core/errors"
	corepolicy "github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/service"
	coretemplate "github.com/agile-crypto/citius-core/template"
	"github.com/agile-crypto/citius-server/internal/app"
	"github.com/agile-crypto/citius-server/internal/grpc/authz"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
	"github.com/agile-crypto/citius-server/internal/storage"
	"github.com/agile-crypto/vault-storage/key"
	"github.com/agile-crypto/vault-storage/policy"
	"github.com/agile-crypto/vault-storage/template"
	"github.com/hashicorp/vault/sdk/logical"
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

// WireFactorySet assembles the dependency graph for the deployment of the gRPC server over an in-memory
// [logical.Storage]. This method wires the per-request factory functions used the per-request
// to build orchestrators, registries, and policy engine.
//
// It mirrors today's deployment exactly:
//
//   - The template catalogue is built at startup from the catalogue JSON, and fixed afterwards.
//     Only a reference to it is threaded through per request, so that the catalogue is shared across all requests.
//   - The provider registry is built at startup and fixed afterwards. Only a reference to it is threaded through
//     per request, so that the registry is shared across all requests.
//   - Everything else gets its own factory, for a per-request construction.
//   - All share the same underlying storage.
//
// Authorization is enabled by default: the checks come from
// internal/grpc/authz, which allows every request when no claims are attached
// to the context. A deployment that means to run without per-resource
// authorization should use AllowAllKeyNames() / AllowAllPolicyNames() instead.
//
// A change to SQL or remote storage would be a change to the wiring here, not to the gRPC handlers or the domain services.
//
// TODO(embed): embed.Core (citius-server/embed) calls this with no way to
// override the InmemStorage below, so every embedded Core is ephemeral --
// state is lost when the embedding process exits. Acceptable for now; needs
// a real option once an embedding application wants persistence.
func WireFactorySet(ctx context.Context, cfg Config) (FactorySet, error) {
	const op engerr.Op = "server.WireFactorySet"
	store := &logical.InmemStorage{}
	return wireFactoriesWithStorage(ctx, cfg, store, op)
}

func wireFactoriesWithStorage(ctx context.Context, cfg Config, store storage.Storage, op engerr.Op) (FactorySet, error) {
	templateReg, err := buildTemplateRegistry(ctx, store, cfg.CatalogPath)
	if err != nil {
		return FactorySet{}, engerr.Wrap(ctx, op, err)
	}
	templatesFn := func(context.Context) (coretemplate.Registry, error) {
		return templateReg, nil
	}

	providerReg, err := buildProviderRegistry(ctx, templateReg, cfg.FIPSConfigPath)
	if err != nil {
		return FactorySet{}, engerr.Wrap(ctx, op, err)
	}
	providersFn := func(context.Context) (provider.Registry, error) {
		return providerReg, nil
	}

	keysFn := func(context.Context) (service.KeyOrchestrator, error) {
		return buildVaultKeyOrchestrator(ctx, store, templateReg, providerReg)
	}
	cryptoFn := func(context.Context) (service.CryptoOrchestrator, error) {
		return buildVaultCryptoOrchestrator(ctx, store, templateReg, providerReg)
	}
	policyFn := func(context.Context) (corepolicy.Engine, error) {
		return buildVaultPolicyEngine(ctx, store)
	}

	// TODO: provider instance management is not implemented yet; the stub keeps
	// ProviderService registrable without pretending to persist.
	instanceFn := func(context.Context) (provider.InstanceManager, error) {
		return &noopInstanceManager{}, nil
	}

	keyAuthz := authz.AuthorizeKeyName()
	policyAuthz := authz.AuthorizePolicyName()

	return FactorySet{
		Keys:      keysFn,
		Crypto:    cryptoFn,
		Policy:    policyFn,
		Instances: instanceFn,
		Templates: templatesFn,
		Catalog:   providersFn,

		AuthorizeKey:    keyAuthz,
		AuthorizePolicy: policyAuthz,
	}, nil
}

// AllServices returns a Services with every service enabled, for a deployment
// that serves everything. A deployment that serves only a subset of services
// should construct its own Services value instead.
func AllServices() Services {
	return Services{
		KeyManagement:    true,
		Crypto:           true,
		CryptoPolicy:     true,
		Discovery:        true,
		Provider:         true,
		KeyEstablishment: true,
		Streaming:        true,
	}
}

// ============================================================================
// Shared bootstrap helpers (used by both WireFactorySet and NewTestableServer)
// ============================================================================

// buildTemplateRegistry creates a VaultRegistry and optionally loads the
// standard algorithm catalog from disk.
func buildTemplateRegistry(
	ctx context.Context,
	bootstrapStorage storage.Storage,
	catalogPath string,
) (coretemplate.Registry, error) {
	const op engerr.Op = "server.buildTemplateRegistry"
	reg, err := template.NewVaultRegistry(ctx, bootstrapStorage)
	if err != nil {
		return nil, engerr.Wrap(ctx, op, err)
	}
	if catalogPath != "" {
		if err := coretemplate.LoadStandardCatalog(ctx, catalogPath, reg); err != nil {
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
	templateReg coretemplate.Registry,
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

// ============================================================================
// Factory builders — same pattern as integration tests
// ============================================================================

func buildVaultKeyOrchestrator(
	ctx context.Context, s storage.Storage,
	templateReg coretemplate.Registry, providerReg provider.Registry,
) (service.KeyOrchestrator, error) {
	repo, err := key.NewVaultRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	policyRepo, err := policy.NewVaultRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	pol, err := corepolicy.NewEnforcer(policyRepo, corepolicy.NewSimpleRulesEvaluator())
	if err != nil {
		return nil, err
	}
	return service.NewKeyOrchestrator(repo, templateReg, providerReg, pol)
}

func buildVaultCryptoOrchestrator(
	ctx context.Context, s storage.Storage,
	templateReg coretemplate.Registry, providerReg provider.Registry,
) (service.CryptoOrchestrator, error) {
	repo, err := key.NewVaultRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	policyRepo, err := policy.NewVaultRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	pol, err := corepolicy.NewEnforcer(policyRepo, corepolicy.NewSimpleRulesEvaluator())
	if err != nil {
		return nil, err
	}
	return service.NewCryptoOrchestrator(repo, pol, providerReg, templateReg)
}

func buildVaultPolicyEngine(
	ctx context.Context, s storage.Storage,
) (corepolicy.Engine, error) {
	policyRepo, err := policy.NewVaultRepository(ctx, s)
	if err != nil {
		return nil, err
	}
	return corepolicy.NewEnforcer(policyRepo, corepolicy.NewSimpleRulesEvaluator())
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
