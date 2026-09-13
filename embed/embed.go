// Package embed exposes citius-server's gRPC handlers for direct, in-process
// use by an embedding Go program — most notably go-sdk's embedded submodule.
//
// Unlike internal/cmd/server, this package is not internal/: it is the
// stable, public boundary a caller outside this module builds against. It
// deliberately exposes handlers typed as citius-api-go's generated server
// interfaces, not citius-server's internal concrete handler types, so a
// caller depends only on the proto-derived shape, never on how a handler is
// constructed or wired internally.
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
	server.Config
	Services server.Services
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
	factorySet, err := server.WireFactorySet(ctx, cfg.Config)
	if err != nil {
		return nil, err
	}
	handlers, err := server.BuildHandlers(ctx, cfg.Services, factorySet)
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
