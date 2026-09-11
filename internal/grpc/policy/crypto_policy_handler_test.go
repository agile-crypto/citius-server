// Tests replicated from the monolithic internal/grpc handler suite, so that
// each service handler is covered where it now lives. The assertions are
// unchanged; only the wiring differs — the handler is built from a factory
// closure over the mock instead of a ServiceGateway/scope pair.

package policygrpc_test

import (
	"context"
	"testing"

	storepb "github.com/agile-crypto/citius-server/gen/go/server/store"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	policygrpc "github.com/agile-crypto/citius-server/internal/grpc/policy"
	"github.com/agile-crypto/citius-server/internal/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockPolicyManager stubs policy.Manager. Only the three CRUD methods exercised
// by CreateCryptoPolicy/ReadCryptoPolicy/UpdateCryptoPolicy are wired;
// DeletePolicy and ListPolicies panic to catch accidental calls.
type mockPolicyManager struct {
	createFn func(ctx context.Context, p *policy.Policy) (*policy.Policy, error)
	getFn    func(ctx context.Context, name string) (*policy.Policy, error)
	updateFn func(ctx context.Context, p *policy.Policy) error
}

func (m *mockPolicyManager) CreatePolicy(ctx context.Context, p *policy.Policy) (*policy.Policy, error) {
	if m.createFn != nil {
		return m.createFn(ctx, p)
	}
	panic("mockPolicyManager.CreatePolicy: not implemented")
}
func (m *mockPolicyManager) GetPolicy(ctx context.Context, name string) (*policy.Policy, error) {
	if m.getFn != nil {
		return m.getFn(ctx, name)
	}
	panic("mockPolicyManager.GetPolicy: not implemented")
}
func (m *mockPolicyManager) UpdatePolicy(ctx context.Context, p *policy.Policy) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, p)
	}
	panic("mockPolicyManager.UpdatePolicy: not implemented")
}
func (m *mockPolicyManager) DeletePolicy(_ context.Context, _ string) error {
	panic("mockPolicyManager.DeletePolicy: not implemented")
}
func (m *mockPolicyManager) ListPolicies(_ context.Context) ([]*policy.Policy, error) {
	panic("mockPolicyManager.ListPolicies: not implemented")
}
func (m *mockPolicyManager) ValidateOperation(_ context.Context, _ string, _ core.Operation, _, _ string) error {
	panic("mockPolicyManager.ValidateOperation: not implemented")
}
func (m *mockPolicyManager) ValidateKeyCreation(_ context.Context, _ string, _ *core.KeyCreationSpec) error {
	panic("mockPolicyManager.ValidateKeyCreation: not implemented")
}
func (m *mockPolicyManager) AllowedTemplates(_ context.Context, _ string, _ *core.ScopeSpecification) ([]string, error) {
	panic("mockPolicyManager.AllowedTemplates: not implemented")
}

// wirePolicy builds the handler under test over a fixed policy engine.
func wirePolicy(t *testing.T, engine policy.Engine) *policygrpc.CryptoPolicyHandler {
	t.Helper()
	newPolicy := policy.EngineFactory(func(_ context.Context) (policy.Engine, error) {
		return engine, nil
	})
	authFn := func(ctx context.Context, op engerr.Op, name string) error {
		return nil
	}
	h, err := policygrpc.New(context.Background(), newPolicy, authFn)
	if err != nil {
		t.Fatalf("policygrpc.New: %v", err)
	}
	return h
}

func TestCryptoPolicyHandler_CreateCryptoPolicy_Success(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		createFn: func(_ context.Context, p *policy.Policy) (*policy.Policy, error) {
			if p.Name() != "tenant-a/strict" {
				t.Errorf("name: got %q want tenant-a/strict", p.Name())
			}
			if string(p.RulesJSON()) != `{"version":1}` {
				t.Errorf("rules_json: got %q", string(p.RulesJSON()))
			}
			return policy.New(&storepb.StoredPolicy{
				PublicId:  p.PublicID(),
				Name:      p.Name(),
				RulesJson: p.RulesJSON(),
			}), nil
		},
	}
	h := wirePolicy(t, pm)

	resp, err := h.CreateCryptoPolicy(ctx, &messagespb.CreateCryptoPolicyRequest{
		Name:           "tenant-a/strict",
		PolicyDocument: `{"version":1}`,
	})
	if err != nil {
		t.Fatalf("CreateCryptoPolicy: %v", err)
	}
	if !resp.GetSuccess() {
		t.Error("expected Success: true")
	}
}

func TestCryptoPolicyHandler_CreateCryptoPolicy_AlreadyExists_ReturnsAlreadyExists(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		createFn: func(ctx context.Context, _ *policy.Policy) (*policy.Policy, error) {
			return nil, engerr.New(ctx, "test", engerr.CodeAlreadyExists, "duplicate")
		},
	}
	h := wirePolicy(t, pm)

	_, err := h.CreateCryptoPolicy(ctx, &messagespb.CreateCryptoPolicyRequest{
		Name:           "dup",
		PolicyDocument: `{}`,
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("expected AlreadyExists, got %v", status.Code(err))
	}
}

func TestCryptoPolicyHandler_CreateCryptoPolicy_EmptyName_ReturnsInvalidArgument(t *testing.T) {
	ctx := context.Background()
	// createFn must not be called — empty name is rejected before getScope.
	h := wirePolicy(t, &mockPolicyManager{})

	_, err := h.CreateCryptoPolicy(ctx, &messagespb.CreateCryptoPolicyRequest{
		Name:           "",
		PolicyDocument: `{}`,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", status.Code(err))
	}
}

// ============================================================================
// ReadCryptoPolicy
// ============================================================================

func TestCryptoPolicyHandler_ReadCryptoPolicy_Success(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		getFn: func(_ context.Context, name string) (*policy.Policy, error) {
			return policy.New(&storepb.StoredPolicy{
				PublicId:  name,
				Name:      name,
				RulesJson: []byte(`{"version":1}`),
			}), nil
		},
	}
	h := wirePolicy(t, pm)

	resp, err := h.ReadCryptoPolicy(ctx, &messagespb.ReadCryptoPolicyRequest{Name: "tenant-a/strict"})
	if err != nil {
		t.Fatalf("ReadCryptoPolicy: %v", err)
	}
	if resp.GetName() != "tenant-a/strict" {
		t.Errorf("name: got %q", resp.GetName())
	}
	if resp.GetPolicyDocument() != `{"version":1}` {
		t.Errorf("policy_document: got %q", resp.GetPolicyDocument())
	}
}

func TestCryptoPolicyHandler_ReadCryptoPolicy_NotFound_ReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		getFn: func(ctx context.Context, _ string) (*policy.Policy, error) {
			return nil, engerr.New(ctx, "test", engerr.CodePolicyNotFound, "not found")
		},
	}
	h := wirePolicy(t, pm)

	_, err := h.ReadCryptoPolicy(ctx, &messagespb.ReadCryptoPolicyRequest{Name: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", status.Code(err))
	}
}

func TestCryptoPolicyHandler_ReadCryptoPolicy_EmptyName_ReturnsInvalidArgument(t *testing.T) {
	ctx := context.Background()
	h := wirePolicy(t, &mockPolicyManager{})

	_, err := h.ReadCryptoPolicy(ctx, &messagespb.ReadCryptoPolicyRequest{Name: ""})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", status.Code(err))
	}
}

// ============================================================================
// UpdateCryptoPolicy
// ============================================================================

func TestCryptoPolicyHandler_UpdateCryptoPolicy_Success(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		updateFn: func(_ context.Context, p *policy.Policy) error {
			if p.Name() != "tenant-a/strict" {
				t.Errorf("name: got %q want tenant-a/strict", p.Name())
			}
			if string(p.RulesJSON()) != `{"version":2}` {
				t.Errorf("rules_json: got %q", string(p.RulesJSON()))
			}
			return nil
		},
	}
	h := wirePolicy(t, pm)

	resp, err := h.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name:           "tenant-a/strict",
		PolicyDocument: `{"version":2}`,
	})
	if err != nil {
		t.Fatalf("UpdateCryptoPolicy: %v", err)
	}
	if !resp.GetSuccess() {
		t.Error("expected Success: true")
	}
}

func TestCryptoPolicyHandler_UpdateCryptoPolicy_NotFound_ReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		updateFn: func(ctx context.Context, _ *policy.Policy) error {
			return engerr.New(ctx, "test", engerr.CodePolicyNotFound, "not found")
		},
	}
	h := wirePolicy(t, pm)

	_, err := h.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name:           "missing",
		PolicyDocument: `{}`,
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", status.Code(err))
	}
}

func TestCryptoPolicyHandler_UpdateCryptoPolicy_EmptyName_ReturnsInvalidArgument(t *testing.T) {
	ctx := context.Background()
	h := wirePolicy(t, &mockPolicyManager{})

	_, err := h.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{Name: ""})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", status.Code(err))
	}
}
