package grpc_test

import (
	"context"
	"testing"

	messagespb "github.com/agile-crypto/citius-server/gen/go/api/messages"
	storepb "github.com/agile-crypto/citius-server/gen/go/server/store"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ============================================================================
// CreateCryptoPolicy
// ============================================================================

func TestHandler_CreateCryptoPolicy_Success(t *testing.T) {
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
	h := wireHandlerWithPolicy(nil, nil, pm)

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

func TestHandler_CreateCryptoPolicy_AlreadyExists_ReturnsAlreadyExists(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		createFn: func(ctx context.Context, _ *policy.Policy) (*policy.Policy, error) {
			return nil, engerr.New(ctx, "test", engerr.CodeAlreadyExists, "duplicate")
		},
	}
	h := wireHandlerWithPolicy(nil, nil, pm)

	_, err := h.CreateCryptoPolicy(ctx, &messagespb.CreateCryptoPolicyRequest{
		Name:           "dup",
		PolicyDocument: `{}`,
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("expected AlreadyExists, got %v", status.Code(err))
	}
}

func TestHandler_CreateCryptoPolicy_EmptyName_ReturnsInvalidArgument(t *testing.T) {
	ctx := context.Background()
	// createFn must not be called — empty name is rejected before getScope.
	h := wireHandlerWithPolicy(nil, nil, &mockPolicyManager{})

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

func TestHandler_ReadCryptoPolicy_Success(t *testing.T) {
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
	h := wireHandlerWithPolicy(nil, nil, pm)

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

func TestHandler_ReadCryptoPolicy_NotFound_ReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		getFn: func(ctx context.Context, _ string) (*policy.Policy, error) {
			return nil, engerr.New(ctx, "test", engerr.CodePolicyNotFound, "not found")
		},
	}
	h := wireHandlerWithPolicy(nil, nil, pm)

	_, err := h.ReadCryptoPolicy(ctx, &messagespb.ReadCryptoPolicyRequest{Name: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", status.Code(err))
	}
}

func TestHandler_ReadCryptoPolicy_EmptyName_ReturnsInvalidArgument(t *testing.T) {
	ctx := context.Background()
	h := wireHandlerWithPolicy(nil, nil, &mockPolicyManager{})

	_, err := h.ReadCryptoPolicy(ctx, &messagespb.ReadCryptoPolicyRequest{Name: ""})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", status.Code(err))
	}
}

// ============================================================================
// UpdateCryptoPolicy
// ============================================================================

func TestHandler_UpdateCryptoPolicy_Success(t *testing.T) {
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
	h := wireHandlerWithPolicy(nil, nil, pm)

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

func TestHandler_UpdateCryptoPolicy_NotFound_ReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		updateFn: func(ctx context.Context, _ *policy.Policy) error {
			return engerr.New(ctx, "test", engerr.CodePolicyNotFound, "not found")
		},
	}
	h := wireHandlerWithPolicy(nil, nil, pm)

	_, err := h.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name:           "missing",
		PolicyDocument: `{}`,
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("expected NotFound, got %v", status.Code(err))
	}
}

func TestHandler_UpdateCryptoPolicy_EmptyName_ReturnsInvalidArgument(t *testing.T) {
	ctx := context.Background()
	h := wireHandlerWithPolicy(nil, nil, &mockPolicyManager{})

	_, err := h.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{Name: ""})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", status.Code(err))
	}
}
