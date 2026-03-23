package policy

import (
	"context"

	"github.ibm.com/citius/citius-server/internal/core"
)

// PolicyEvaluator validates operations and key creation against stored policies.
// This is the interface that KeyOrchestrator and CryptoOrchestrator should depend on.
// Denial IS the error — methods return nil on allow, typed error on deny.
type PolicyEvaluator interface {
	// ValidateOperation checks whether a crypto operation is allowed under the named policy.
	// Use ValidateKeyCreation for pre-checking CreateKey operations with client-supplied specifications.
	// Returns nil if allowed; returns a typed error (with denial reason) if denied.
	ValidateOperation(ctx context.Context, policyName string,
		operation core.Operation, templateID string, providerID string) error

	// ValidateKeyCreation checks whether a key may be created with the given spec.
	ValidateKeyCreation(ctx context.Context, policyName string, spec *core.KeyCreationSpec) error

	// AllowedTemplates returns the template IDs permitted for the given scope by the named policy.
	// Returns nil if the policy imposes no template restriction.
	AllowedTemplates(ctx context.Context, policyName string, scopeSpec core.ScopeSpec) ([]string, error)
}

// PolicyManager handles policy CRUD lifecycle.
// This is the interface that the policy gRPC handler should depend on.
type PolicyManager interface {
	CreatePolicy(ctx context.Context, p *Policy) (*Policy, error)
	GetPolicy(ctx context.Context, name string) (*Policy, error)
	UpdatePolicy(ctx context.Context, p *Policy) error
	DeletePolicy(ctx context.Context, name string) error
	ListPolicies(ctx context.Context) ([]*Policy, error)
}

// Engine is the full policy interface. Enforcer implements this.
// Consumers should prefer the narrow interface they actually need:
//   - KeyOrchestrator/CryptoOrchestrator => PolicyEvaluator
//   - Policy gRPC handler => PolicyManager (and optionally PolicyEvaluator for EvaluatePolicy)
type Engine interface {
	PolicyEvaluator
	PolicyManager
}
