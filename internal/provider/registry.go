package provider

import (
	"context"

	"github.ibm.com/citius/citius-server/internal/core"
)

// Registry manages the set of available Backend implementations.
type Registry interface {
	Register(ctx context.Context, p Backend) error
	Get(ctx context.Context, name string) (Backend, error)
	GetDefault(ctx context.Context) (Backend, error)
	List(ctx context.Context) []Backend
	Remove(ctx context.Context, name string) error
	MatchForTemplate(ctx context.Context, templateID string) (Backend, error)
	MatchForScope(ctx context.Context, scope core.ScopeSpec) (Backend, error)
}
