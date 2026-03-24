package policy

import (
	"context"

	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"google.golang.org/protobuf/proto"
)

// Policy is the domain representation of an access-control / algorithm policy.
type Policy struct {
	stored *storepb.StoredPolicy
}

// New wraps a StoredPolicy.
func New(stored *storepb.StoredPolicy) *Policy {
	if stored == nil {
		stored = &storepb.StoredPolicy{}
	}
	return &Policy{stored: stored}
}

func (p *Policy) StoredPolicy() *storepb.StoredPolicy { return p.stored }

func (p *Policy) PublicID() string { return p.stored.GetPublicId() }

func (p *Policy) Name() string { return p.stored.GetName() }

// Callers should use Clone() before mutating.
func (p *Policy) Clone() *Policy {
	return &Policy{stored: proto.Clone(p.stored).(*storepb.StoredPolicy)}
}

// VetForWrite validates the Policy.
func (p *Policy) VetForWrite(ctx context.Context, op core.WriteOp) error {
	const opVet errors.Op = "policy.(Policy).VetForWrite"
	switch op {
	case core.OpCreate, core.OpUpdate:
		if p.stored.GetPublicId() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "public_id is required")
		}
		if p.stored.GetName() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "name is required")
		}
	case core.OpDelete:
		// No additional validation required for delete.
	}
	return nil
}

// Behavioral Methods
//
// TODO: AllowsOperation(operation core.Operation) bool and AllowsTemplate(templateID string) bool
// are deferred. StoredPolicy uses an opaque `rules_json` blob rather than discrete
// AllowedOperations / AllowedAlgorithms repeated-string fields. These behavioural
// methods will be implemented when the policy rules engine (PolicyEngine) parses
// rules_json when implementing the PolicyEngine.
// See proto/store/policy.proto.

var _ core.VetForWriter = (*Policy)(nil)
