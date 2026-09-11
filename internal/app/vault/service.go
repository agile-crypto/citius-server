//go:build vault_plugin

package vault

import (
	"context"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/template"
	"github.com/agile-crypto/citius-server/internal/service"
	"github.com/agile-crypto/citius-server/internal/storage"
)

const (
	opNew        errors.Op = "app.(Service).NewService"
	opForStorage errors.Op = "app.(Service).ForStorage"
)

// Service is the top-level facade for the core.
// It holds the factory functions and shared registries.
// Create one Service at startup via NewService; call ForStorage per request.
type Service struct {
	keyOrchestratorFn    KeyOrchestratorFactory
	cryptoOrchestratorFn CryptoOrchestratorFactory
	policyEngineFn       PolicyEngineFactory
	providerInstanceFn   ProviderInstanceManagerFactory
	templates            template.Registry
	providers            provider.Registry
}

// NewService creates a Service from the provided options.
// Returns an error if any required option is missing (nil).
func NewService(opts ...Option) (*Service, error) {
	s := &Service{}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// validate checks that all required fields are non-nil.
func (s *Service) validate() error {
	ctx := context.Background()
	switch {
	case s.keyOrchestratorFn == nil:
		return errors.New(ctx, opNew, errors.CodeInvalidArgument, "KeyOrchestratorFactory is required")
	case s.cryptoOrchestratorFn == nil:
		return errors.New(ctx, opNew, errors.CodeInvalidArgument, "CryptoOrchestratorFactory is required")
	case s.policyEngineFn == nil:
		return errors.New(ctx, opNew, errors.CodeInvalidArgument, "PolicyEngineFactory is required")
	case s.providerInstanceFn == nil:
		return errors.New(ctx, opNew, errors.CodeInvalidArgument, "ProviderInstanceManagerFactory is required")
	case s.templates == nil:
		return errors.New(ctx, opNew, errors.CodeInvalidArgument, "TemplateRegistry is required")
	case s.providers == nil:
		return errors.New(ctx, opNew, errors.CodeInvalidArgument, "ProviderRegistry is required")
	}
	return nil
}

// ForStorage calls all four factories with the given Storage and returns a
// *RequestScope ready for a single request's use.
func (s *Service) ForStorage(ctx context.Context, store storage.Storage) (*RequestScope, error) {
	keys, err := s.keyOrchestratorFn(store)
	if err != nil {
		return nil, errors.Wrap(ctx, opForStorage, err)
	}
	cryptoOps, err := s.cryptoOrchestratorFn(store)
	if err != nil {
		return nil, errors.Wrap(ctx, opForStorage, err)
	}
	pol, err := s.policyEngineFn(store)
	if err != nil {
		return nil, errors.Wrap(ctx, opForStorage, err)
	}
	pi, err := s.providerInstanceFn(store)
	if err != nil {
		return nil, errors.Wrap(ctx, opForStorage, err)
	}
	return &RequestScope{
		keys:              keys,
		cryptoOps:         cryptoOps,
		policy:            pol,
		providerInstances: pi,
		templates:         s.templates,
		providers:         s.providers,
	}, nil
}

// RequestScope holds the per-request instances of all core subsystems.
// Obtain one by calling Service.ForStorage.
type RequestScope struct {
	keys              service.KeyOrchestrator
	cryptoOps         service.CryptoOrchestrator
	policy            policy.Engine
	providerInstances provider.InstanceManager
	templates         template.Registry
	providers         provider.Registry
}

func (r *RequestScope) Keys() service.KeyOrchestrator { return r.keys }

func (r *RequestScope) Crypto() service.CryptoOrchestrator { return r.cryptoOps }

func (r *RequestScope) Policy() policy.Engine { return r.policy }

func (r *RequestScope) ProviderInstances() provider.InstanceManager { return r.providerInstances }

func (r *RequestScope) Templates() template.Registry { return r.templates }

func (r *RequestScope) Providers() provider.Registry { return r.providers }
