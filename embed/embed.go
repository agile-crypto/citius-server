// Package embed exposes citius-server's gRPC handlers for direct, in-process
// use by an embedding Go program — most notably go-sdk's embedded submodule.
//
// Unlike internal/cmd/server, this package is not internal/: it is the
// stable, public boundary a caller outside this module builds against. Every
// exported type here is either a plain value type owned by this package or a
// citius-api-go-generated proto/service type — never a type named in
// internal/cmd/server — so a caller never needs to (and, being outside this
// module, cannot) name an internal/ type to use this package.
//
// There is no gRPC transport involved here: Core's accessors return the
// handler values directly, for a caller to invoke as plain Go method calls.
package embed

import (
	"context"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	server "github.com/agile-crypto/citius-server/internal/cmd/server"
)

// Config configures an embedded Core: which services to build handlers for,
// plus the same wiring knobs internal/cmd/server.Config exposes (catalog
// path, FIPS config).
type Config struct {
	// CatalogPath is the path to the proto-JSON standard_algorithms.json
	// file. When empty, no catalog is loaded (useful for testing).
	CatalogPath string

	// FIPSConfigPath is an OpenSSL config activating the fips provider; see
	// internal/cmd/server.Config's doc comment for the exact shape
	// required. When empty, no FIPS provider instance is registered.
	FIPSConfigPath string

	// Services selects which handlers New builds.
	Services Services
}

// Services selects which per-service handlers Core exposes. The zero value
// selects none.
type Services struct {
	KeyManagement    bool
	Crypto           bool
	CryptoPolicy     bool
	Discovery        bool
	Provider         bool
	KeyEstablishment bool
	Streaming        bool
}

// Core holds the handlers built for an embedded deployment. A nil accessor
// return means that service was not selected in Config.Services.
type Core struct {
	handlers *server.Handlers
}

// New builds a Core: the same wiring internal/cmd/server.WireFactorySet
// produces, with handlers constructed directly (server.BuildHandlers)
// rather than registered onto a grpc.ServiceRegistrar.
func New(ctx context.Context, cfg Config) (*Core, error) {
	factorySet, err := server.WireFactorySet(ctx, server.Config{
		CatalogPath:    cfg.CatalogPath,
		FIPSConfigPath: cfg.FIPSConfigPath,
	})
	if err != nil {
		return nil, err
	}
	handlers, err := server.BuildHandlers(ctx, server.Services{
		KeyManagement:    cfg.Services.KeyManagement,
		Crypto:           cfg.Services.Crypto,
		CryptoPolicy:     cfg.Services.CryptoPolicy,
		Discovery:        cfg.Services.Discovery,
		Provider:         cfg.Services.Provider,
		KeyEstablishment: cfg.Services.KeyEstablishment,
		Streaming:        cfg.Services.Streaming,
	}, factorySet)
	if err != nil {
		return nil, err
	}
	return &Core{handlers: handlers}, nil
}

// KeyManagementHandler returns the KeyManagementService handler, or nil if
// Config.Services.KeyManagement was false.
func (c *Core) KeyManagementHandler() servicespb.KeyManagementServiceServer {
	return c.handlers.KeyManagement
}

// CryptoHandler returns the CryptoService handler, or nil if
// Config.Services.Crypto was false.
func (c *Core) CryptoHandler() servicespb.CryptoServiceServer {
	return c.handlers.Crypto
}

// CryptoPolicyHandler returns the CryptoPolicyService handler, or nil if
// Config.Services.CryptoPolicy was false.
func (c *Core) CryptoPolicyHandler() servicespb.CryptoPolicyServiceServer {
	return c.handlers.CryptoPolicy
}

// DiscoveryHandler returns the AlgorithmDiscoveryService handler, or nil if
// Config.Services.Discovery was false.
func (c *Core) DiscoveryHandler() servicespb.AlgorithmDiscoveryServiceServer {
	return c.handlers.Discovery
}

// ProviderHandler returns the ProviderService handler, or nil if
// Config.Services.Provider was false.
func (c *Core) ProviderHandler() servicespb.ProviderServiceServer {
	return c.handlers.Provider
}

// KeyEstablishmentHandler returns the KeyEstablishmentService handler, or
// nil if Config.Services.KeyEstablishment was false.
func (c *Core) KeyEstablishmentHandler() servicespb.KeyEstablishmentServiceServer {
	return c.handlers.KeyEstablishment
}

// StreamingHandler returns the StreamingCryptoService handler, or nil if
// Config.Services.Streaming was false.
func (c *Core) StreamingHandler() servicespb.StreamingCryptoServiceServer {
	return c.handlers.Streaming
}
