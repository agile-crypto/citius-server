package policy

import (
	"context"

	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
)

// Enforcer implements policy.Engine.
// It stores and retrieves policies from the provided Repository, and evaluates
// operations against those policies.
type Enforcer struct {
	store Repository
}

// NewEnforcer creates an Enforcer backed by the given Repository.
// Returns an error if repo is nil.
func NewEnforcer(s Repository) (*Enforcer, error) {
	const op errors.Op = "policy.NewEnforcer"
	if s == nil {
		return nil, errors.New(context.Background(), op, errors.CodeInvalidArgument,
			"repository must not be nil")
	}
	return &Enforcer{store: s}, nil
}

// ---- Policy CRUD ----

func (r *Enforcer) CreatePolicy(ctx context.Context, p *Policy) (*Policy, error) {
	const op errors.Op = "policy.(Enforcer).CreatePolicy"
	if p == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "policy must not be nil")
	}
	if err := p.VetForWrite(ctx, core.OpCreate); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	// Check for duplicate
	if _, err := r.store.GetPolicy(ctx, p.Name()); err == nil {
		return nil, errors.New(ctx, op, errors.CodeAlreadyExists,
			"policy already exists: "+p.Name())
	}
	if err := r.store.PutPolicy(ctx, p); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return r.store.GetPolicy(ctx, p.Name())
}

func (r *Enforcer) GetPolicy(ctx context.Context, name string) (*Policy, error) {
	const op errors.Op = "policy.(Enforcer).GetPolicy"
	p, err := r.store.GetPolicy(ctx, name)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return p, nil
}

func (r *Enforcer) UpdatePolicy(ctx context.Context, p *Policy) error {
	const op errors.Op = "policy.(Enforcer).UpdatePolicy"
	if p == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "policy must not be nil")
	}
	if err := p.VetForWrite(ctx, core.OpUpdate); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	// Verify policy exists before update
	if _, err := r.store.GetPolicy(ctx, p.Name()); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if err := r.store.PutPolicy(ctx, p); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *Enforcer) DeletePolicy(ctx context.Context, name string) error {
	const op errors.Op = "policy.(Enforcer).DeletePolicy"
	if err := r.store.DeletePolicy(ctx, name); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *Enforcer) ListPolicies(ctx context.Context) ([]*Policy, error) {
	const op errors.Op = "policy.(Enforcer).ListPolicies"
	ids, err := r.store.ListPolicies(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	out := make([]*Policy, 0, len(ids))
	for _, id := range ids {
		p, err := r.store.GetPolicy(ctx, id)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// ---- Evaluation stubs (TODO: Implement them later) ----

// ValidateOperation is a stub - all operations are allowed.
func (r *Enforcer) ValidateOperation(_ context.Context, _ string, _ core.Operation, _, _ string) error {
	return nil
}

// ValidateKeyCreation is a stub — all key creation is allowed.
func (r *Enforcer) ValidateKeyCreation(_ context.Context, _ string, _ *core.KeyCreationSpec) error {
	return nil
}

// AllowedTemplates is a stub — returns nil (no restriction, all templates allowed).
func (r *Enforcer) AllowedTemplates(_ context.Context, _ string, _ core.ScopeSpec) ([]string, error) {
	return nil, nil
}

// Compile-time assertion - TODO: uncomment when all policy.Engine methods are implemented.
// var _ Engine = (*Enforcer)(nil)
