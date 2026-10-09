// Tests replicated from the monolithic internal/grpc handler suite, so that
// each service handler is covered where it now lives. The assertions are
// unchanged; only the wiring differs — the handler is built from a factory
// closure over the mock instead of a ServiceGateway/scope pair.

package policygrpc_test

import (
	"context"
	"testing"
	"time"

	storepb "github.com/agile-crypto/citius-core/store"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
	policygrpc "github.com/agile-crypto/citius-server/internal/grpc/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockPolicyManager stubs policy.Manager. Only the three CRUD methods exercised
// by CreateCryptoPolicy/ReadCryptoPolicy/UpdateCryptoPolicy are wired;
// DeletePolicy and ListPolicies panic to catch accidental calls.
type mockPolicyManager struct {
	createFn func(ctx context.Context, p *policy.Policy) (*policy.Policy, error)
	getFn    func(ctx context.Context, name string) (*policy.Policy, error)
	updateFn func(ctx context.Context, p *policy.Policy, expectedVersion int64) (*policy.Policy, error)
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
func (m *mockPolicyManager) UpdatePolicy(ctx context.Context, p *policy.Policy, expectedVersion int64) (*policy.Policy, error) {
	if m.updateFn != nil {
		return m.updateFn(ctx, p, expectedVersion)
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
func (m *mockPolicyManager) ProviderRequirements(_ context.Context, _ string) (core.ProviderRequirements, error) {
	panic("mockPolicyManager.ProviderRequirements: not implemented")
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
				Version:   "1",
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
	if resp.GetVersion() != 1 {
		t.Errorf("version = %d, want 1", resp.GetVersion())
	}
}

func TestCryptoPolicyHandler_UnsupportedFormat_ReturnsInvalidArgument(t *testing.T) {
	ctx := context.Background()
	// No engine call is expected: the format is rejected first.
	h := wirePolicy(t, &mockPolicyManager{})

	_, err := h.CreateCryptoPolicy(ctx, &messagespb.CreateCryptoPolicyRequest{
		Name: "p", PolicyDocument: `{}`, Format: "rego",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("create: expected InvalidArgument, got %v", status.Code(err))
	}
	_, err = h.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name: "p", PolicyDocument: `{}`, Format: "cedar",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("update: expected InvalidArgument, got %v", status.Code(err))
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
	created := timestamppb.New(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	updated := timestamppb.New(time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC))
	pm := &mockPolicyManager{
		getFn: func(_ context.Context, name string) (*policy.Policy, error) {
			return policy.New(&storepb.StoredPolicy{
				PublicId:   name,
				Name:       name,
				RulesJson:  []byte(`{"version":1}`),
				Version:    "3",
				CreateTime: created,
				UpdateTime: updated,
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
	if resp.GetFormat() != "json" || resp.GetVersion() != 3 {
		t.Errorf("format/version = %q/%d, want json/3", resp.GetFormat(), resp.GetVersion())
	}
	if !proto.Equal(resp.GetCreatedAt(), created) || !proto.Equal(resp.GetUpdatedAt(), updated) {
		t.Errorf("times = %v/%v, want %v/%v", resp.GetCreatedAt(), resp.GetUpdatedAt(), created, updated)
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
		updateFn: func(_ context.Context, p *policy.Policy, expectedVersion int64) (*policy.Policy, error) {
			if p.Name() != "tenant-a/strict" {
				t.Errorf("name: got %q want tenant-a/strict", p.Name())
			}
			if string(p.RulesJSON()) != `{"version":2}` {
				t.Errorf("rules_json: got %q", string(p.RulesJSON()))
			}
			if expectedVersion != 4 {
				t.Errorf("expected_version passed as %d, want 4", expectedVersion)
			}
			return policy.New(&storepb.StoredPolicy{Name: p.Name(), Version: "5"}), nil
		},
	}
	h := wirePolicy(t, pm)

	resp, err := h.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name:            "tenant-a/strict",
		PolicyDocument:  `{"version":2}`,
		ExpectedVersion: 4,
	})
	if err != nil {
		t.Fatalf("UpdateCryptoPolicy: %v", err)
	}
	if !resp.GetSuccess() {
		t.Error("expected Success: true")
	}
	if resp.GetVersion() != 5 {
		t.Errorf("version = %d, want 5", resp.GetVersion())
	}
}

func TestCryptoPolicyHandler_UpdateCryptoPolicy_VersionConflict_ReturnsFailedPrecondition(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		updateFn: func(ctx context.Context, _ *policy.Policy, _ int64) (*policy.Policy, error) {
			return nil, engerr.New(ctx, "test", engerr.CodeFailedPrecondition, "policy version conflict")
		},
	}
	h := wirePolicy(t, pm)

	_, err := h.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name: "p", PolicyDocument: `{}`, ExpectedVersion: 1,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("expected FailedPrecondition, got %v", status.Code(err))
	}
}

func TestCryptoPolicyHandler_UpdateCryptoPolicy_NotFound_ReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		updateFn: func(ctx context.Context, _ *policy.Policy, _ int64) (*policy.Policy, error) {
			return nil, engerr.New(ctx, "test", engerr.CodePolicyNotFound, "not found")
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
