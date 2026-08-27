package provider

import (
	"context"
	"sync"

	"github.com/agile-crypto/citius-server/internal/core"
	"github.com/agile-crypto/citius-server/internal/errors"
)

// Registry manages the set of available Backend implementations.
type Registry interface {
	Register(ctx context.Context, p Backend) error
	Get(ctx context.Context, name string) (Backend, error)
	GetDefault(ctx context.Context) (Backend, error)
	List(ctx context.Context) []Backend
	Remove(ctx context.Context, name string) error
	MatchForTemplate(ctx context.Context, templateID string) (Backend, error)
	MatchForScope(ctx context.Context, scope *core.ScopeSpecification) (Backend, error)
}

// registry is a thread-safe in-memory registry of provider backends.
type registry struct {
	mu        sync.RWMutex
	providers map[string]Backend
	order     []string // insertion-order for GetDefault fallback

	// byTemplate indexes provider names by the template IDs they advertise
	// via AlgorithmCapabilityProvider.SupportedAlgorithms(), built once at
	// Register time and kept in sync by Remove. Each slice is
	// insertion-ordered, same as order, so MatchForTemplate's "first match
	// wins" behavior is unchanged from the pre-index scan it replaces.
	byTemplate map[string][]string
}

// NewRegistry creates an empty registry.
func NewRegistry() Registry {
	return &registry{
		providers:  make(map[string]Backend),
		byTemplate: make(map[string][]string),
	}
}

func (r *registry) Register(ctx context.Context, p Backend) error {
	const op errors.Op = "provider.(registry).Register"
	if p == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "provider must not be nil")
	}
	name := p.Name()
	if name == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "provider name must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[name]; exists {
		return errors.New(ctx, op, errors.CodeAlreadyExists, "provider already registered: "+name)
	}
	r.providers[name] = p
	r.order = append(r.order, name)
	if sp, ok := p.(interface{ SupportedAlgorithms() []string }); ok {
		for _, alg := range sp.SupportedAlgorithms() {
			r.byTemplate[alg] = append(r.byTemplate[alg], name)
		}
	}
	return nil
}

func (r *registry) Get(ctx context.Context, name string) (Backend, error) {
	const op errors.Op = "provider.(registry).Get"
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	if !ok {
		return nil, errors.New(ctx, op, errors.CodeProviderNotFound, "provider not found: "+name)
	}
	return p, nil
}

func (r *registry) GetDefault(ctx context.Context) (Backend, error) {
	const op errors.Op = "provider.(registry).GetDefault"
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.order) == 0 {
		return nil, errors.New(ctx, op, errors.CodeProviderNotFound, "no providers registered")
	}
	// For now, return the first registered provider.
	// TODO: add IsDefault support via provider metadata.
	// Fallback: first registered provider.
	return r.providers[r.order[0]], nil
}

func (r *registry) List(ctx context.Context) []Backend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Backend, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.providers[name])
	}
	return out
}

func (r *registry) Remove(ctx context.Context, name string) error {
	const op errors.Op = "provider.(registry).Remove"
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.providers[name]
	if !ok {
		return errors.New(ctx, op, errors.CodeProviderNotFound, "provider not found: "+name)
	}
	delete(r.providers, name)
	// Remove from order slice
	for i, n := range r.order {
		if n == name {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	// Evict name from every template entry it was indexed under.
	if sp, ok := p.(interface{ SupportedAlgorithms() []string }); ok {
		for _, alg := range sp.SupportedAlgorithms() {
			names := r.byTemplate[alg]
			for i, n := range names {
				if n == name {
					names = append(names[:i], names[i+1:]...)
					break
				}
			}
			if len(names) == 0 {
				delete(r.byTemplate, alg)
			} else {
				r.byTemplate[alg] = names
			}
		}
	}
	return nil
}

func (r *registry) MatchForTemplate(ctx context.Context, templateID string) (Backend, error) {
	const op errors.Op = "provider.(Registry).MatchForTemplate"
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.order) == 0 {
		return nil, errors.New(ctx, op, errors.CodeProviderNotFound, "no providers registered")
	}

	names := r.byTemplate[templateID]
	if len(names) == 0 {
		return nil, errors.New(ctx, op, errors.CodeProviderNotFound,
			"no provider supports template: "+templateID)
	}
	return r.providers[names[0]], nil
}

// MatchForScope for now delegates to GetDefault.
// TODO: inspect provider capabilities and match on scope.
func (r *registry) MatchForScope(ctx context.Context, scope *core.ScopeSpecification) (Backend, error) {
	const op errors.Op = "provider.(Registry).MatchForScope"
	p, err := r.GetDefault(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return p, nil
}

// compile-time check
var _ Registry = (*registry)(nil)
