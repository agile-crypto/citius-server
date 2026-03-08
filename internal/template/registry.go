package template

import (
	"context"

	"github.ibm.com/citius/citius-server/internal/core"
)

// Registry manages algorithm template definitions and selection.
type Registry interface {
	Register(ctx context.Context, tmpl *Template) error
	Get(ctx context.Context, templateID string) (*Template, error)
	List(ctx context.Context) []*Template

	// Select picks the best template for a scope specification.
	// Core selection algorithm:
	//   1. Filter by scope match
	//   2. Filter by policy-allowed templates (allowedTemplates)
	//   3. Filter by preferred properties (soft — falls back if none match)
	//   4. Return highest-priority active template
	Select(ctx context.Context, scopeSpec core.ScopeSpec,
		allowedTemplates []string,
		preferred map[string]string) (*Template, error)

	// NOTE: LoadFromYAML is intentionally NOT part of this interface.
	// It is a startup/configuration concern implemented as a package-level function
	// in the template package: template.LoadFromYAML(path string, r *Registry) error
}
