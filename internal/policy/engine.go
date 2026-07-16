package policy

import (
	"context"

	"github.com/agile-crypto/citius-server/internal/core"
)

// Evaluator validates operations and key creation against stored policies.
// This is the interface that KeyOrchestrator and CryptoOrchestrator should depend on.
// Denial IS the error — methods return nil on allow, typed error on deny.
type Evaluator interface {
	// ValidateOperation checks whether a crypto operation is allowed under the named policy.
	// Use ValidateKeyCreation for pre-checking CreateKey operations with client-supplied specifications.
	// Returns nil if allowed; returns a typed error (with denial reason) if denied.
	ValidateOperation(ctx context.Context, policyName string,
		operation core.Operation, templateID string, providerID string) error

	// ValidateKeyCreation checks whether a key may be created with the given spec.
	ValidateKeyCreation(ctx context.Context, policyName string, spec *core.KeyCreationSpec) error

	// AllowedTemplates returns the template IDs permitted for the given scope by the named policy.
	// Deny-by-default: absent section returns an empty non-nil slice (nothing allowed).
	// Returns nil only when policyName is empty (bypass).
	AllowedTemplates(ctx context.Context, policyName string, scopeSpec *core.ScopeSpecification) ([]string, error)
}

// Manager handles policy CRUD lifecycle.
// This is the interface that the policy gRPC handler should depend on.
type Manager interface {
	CreatePolicy(ctx context.Context, p *Policy) (*Policy, error)
	GetPolicy(ctx context.Context, name string) (*Policy, error)
	UpdatePolicy(ctx context.Context, p *Policy) error
	DeletePolicy(ctx context.Context, name string) error
	ListPolicies(ctx context.Context) ([]*Policy, error)
}

// Engine is the full policy interface. Enforcer implements this.
// Consumers should prefer the narrow interface they actually need:
//   - KeyOrchestrator/CryptoOrchestrator => Evaluator
//   - Policy gRPC handler => Manager (and optionally Evaluator for EvaluatePolicy)
type Engine interface {
	Evaluator
	Manager
}
