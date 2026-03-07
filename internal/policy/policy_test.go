package policy_test

import (
	"context"
	"testing"

	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/policy"
)

func TestPolicy_VetForWrite_Create_happyPath(t *testing.T) {
	p := policy.New(&storepb.StoredPolicy{
		PublicId: "pol_01HXYZ",
		Name:     "default-sig-policy",
	})
	if err := p.VetForWrite(context.Background(), core.OpCreate); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPolicy_VetForWrite_Create_missingName(t *testing.T) {
	p := policy.New(&storepb.StoredPolicy{PublicId: "pol_01HXYZ"})
	err := p.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing Name")
	}
}

func TestPolicy_Clone_independent(t *testing.T) {
	p := policy.New(&storepb.StoredPolicy{
		PublicId: "pol_01HXYZ",
		Name:     "policy-1",
		Labels:   map[string]string{"team": "security"},
	})
	c := p.Clone()
	c.StoredPolicy().Labels["team"] = "platform"
	if p.StoredPolicy().Labels["team"] != "security" {
		t.Error("Clone() did not produce an independent copy")
	}
}

// TODO: AllowsOperation and AllowsTemplate tests deferred.
// StoredPolicy uses an opaque `rules_json` blob (not discrete AllowedOperations/
// AllowedAlgorithms fields). These behavioural methods will be implemented when
// the policy rules engine parses rules_json in the PolicyEngine.

// Compile-time assertion.
var _ core.VetForWriter = (*policy.Policy)(nil)
