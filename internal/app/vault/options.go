//go:build vault_plugin

package vault

import (
	"github.com/agile-crypto/citius-server/internal/policy"
	"github.com/agile-crypto/citius-server/internal/provider"
	"github.com/agile-crypto/citius-server/internal/service"
	"github.com/agile-crypto/citius-server/internal/storage"
	"github.com/agile-crypto/citius-server/internal/template"
)

// ============================================================================
// Factory type aliases
// ============================================================================

type KeyOrchestratorFactory func(storage.Storage) (service.KeyOrchestrator, error)

type CryptoOrchestratorFactory func(storage.Storage) (service.CryptoOrchestrator, error)

type PolicyEngineFactory func(storage.Storage) (policy.Engine, error)

type ProviderInstanceManagerFactory func(storage.Storage) (provider.InstanceManager, error)

// Option is a functional option for configuring a Service.
type Option func(*Service)

func WithKeyOrchestratorFactory(f KeyOrchestratorFactory) Option {
	return func(s *Service) { s.keyOrchestratorFn = f }
}

func WithCryptoOrchestratorFactory(f CryptoOrchestratorFactory) Option {
	return func(s *Service) { s.cryptoOrchestratorFn = f }
}

func WithPolicyEngineFactory(f PolicyEngineFactory) Option {
	return func(s *Service) { s.policyEngineFn = f }
}

func WithProviderInstanceManagerFactory(f ProviderInstanceManagerFactory) Option {
	return func(s *Service) { s.providerInstanceFn = f }
}

// WithTemplateRegistry sets the shared (request-independent) template.Registry.
func WithTemplateRegistry(r template.Registry) Option {
	return func(s *Service) { s.templates = r }
}

// WithProviderRegistry sets the shared (request-independent) provider.Registry.
func WithProviderRegistry(r provider.Registry) Option {
	return func(s *Service) { s.providers = r }
}
