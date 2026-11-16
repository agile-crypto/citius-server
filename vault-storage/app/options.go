//go:build vault_plugin

package app

import (
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	cryptosvc "github.com/agile-crypto/citius-core/service/crypto"
	keysvc "github.com/agile-crypto/citius-core/service/key"
	"github.com/agile-crypto/citius-core/template"
	"github.com/hashicorp/vault/sdk/logical"
)

// ============================================================================
// Factory type aliases
// ============================================================================

type KeyOrchestratorFactory func(logical.Storage) (keysvc.KeyOrchestrator, error)

type CryptoOrchestratorFactory func(logical.Storage) (cryptosvc.CryptoOrchestrator, error)

type PolicyEngineFactory func(logical.Storage) (policy.Engine, error)

type ProviderInstanceManagerFactory func(logical.Storage) (provider.InstanceManager, error)

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
