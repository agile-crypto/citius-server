package policy

import (
	"context"

	"github.ibm.com/citius/citius-server/internal/core"
)

// Engine validates operations and key creation against stored policies.
// Denial IS the error — ValidateOperation returns nil on allow, typed error on deny
//
// Currently all interface methods are combined.
// TODO: Consider splitting into separate PolicyRepository and PolicyEvaluator interfaces
// so consumers can depend on only the role they need:
//   - KeyOrchestrator/CryptoOrchestrator => PolicyEvaluator (validation only)
//   - PolicyHandler (gRPC) => PolicyRepository (CRUD only)
type Engine interface {

	// ValidateOperation checks whether a crypto operation is allowed under the named policy.
	// Use ValidateKeyCreation for pre-checking CreateKey operations with client-supplied specifications.
	// Returns nil if allowed; returns a typed error (with denial reason) if denied.
	ValidateOperation(ctx context.Context, policyName string,
		operation core.Operation, templateID string, providerID string) error

	// ValidateKeyCreation checks whether a key may be created with the given spec.
	ValidateKeyCreation(ctx context.Context, policyName string, spec *core.KeyCreationSpec) error

	// AllowedTemplates returns the template IDs permitted for the given scope by the named policy.
	AllowedTemplates(ctx context.Context, policyName string, scopeSpec core.ScopeSpec) ([]string, error)

	// --- Policy CRUD methods --- //

	CreatePolicy(ctx context.Context, p *Policy) (*Policy, error)
	GetPolicy(ctx context.Context, name string) (*Policy, error)
	UpdatePolicy(ctx context.Context, p *Policy) error
	DeletePolicy(ctx context.Context, name string) error
	ListPolicies(ctx context.Context) ([]*Policy, error)
}
