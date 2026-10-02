// Tests replicated from the monolithic internal/grpc handler suite, so that
// each service handler is covered where it now lives. The assertions are
// unchanged; only the wiring differs — the handler is built from a factory
// closure over the mock instead of a ServiceGateway/scope pair.

package policygrpc_test

import (
	"context"
	"slices"
	"testing"
	"time"

	storepb "github.com/agile-crypto/citius-core/store"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
	policygrpc "github.com/agile-crypto/citius-server/internal/grpc/policy"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockPolicyManager stubs policy.Engine. Only the three CRUD methods exercised
// by CreateCryptoPolicy/ReadCryptoPolicy/UpdateCryptoPolicy and AllowedTemplates
// (ListAllowedAlgorithms) are wired; the others panic to catch accidental calls.
type mockPolicyManager struct {
	createFn           func(ctx context.Context, p *policy.Policy) (*policy.Policy, error)
	getFn              func(ctx context.Context, name string) (*policy.Policy, error)
	updateFn           func(ctx context.Context, p *policy.Policy, expectedVersion int64) (*policy.Policy, error)
	allowedTemplatesFn func(ctx context.Context, policyName string, scopeSpec *core.ScopeSpecification) ([]string, error)
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
func (m *mockPolicyManager) AllowedTemplates(ctx context.Context, policyName string, scopeSpec *core.ScopeSpecification) ([]string, error) {
	if m.allowedTemplatesFn != nil {
		return m.allowedTemplatesFn(ctx, policyName, scopeSpec)
	}
	panic("mockPolicyManager.AllowedTemplates: not implemented")
}
func (m *mockPolicyManager) ProviderRequirements(_ context.Context, _ string) (core.ProviderRequirements, error) {
	panic("mockPolicyManager.ProviderRequirements: not implemented")
}

// wirePolicy builds the handler under test over a fixed policy engine, with
// policy authorization always allowing.
func wirePolicy(t *testing.T, engine policy.Engine) *policygrpc.CryptoPolicyHandler {
	t.Helper()
	newPolicy := policy.EngineFactory(func(_ context.Context) (policy.Engine, error) {
		return engine, nil
	})
	authFn := func(ctx context.Context, op engerr.Op, name string) error {
		return nil
	}
	return wirePolicyFactory(t, newPolicy, authFn)
}

// wirePolicyFactory builds the handler under test from newPolicy and the
// given policy authorization check.
func wirePolicyFactory(t *testing.T, newPolicy policy.EngineFactory, authorizePolicy grpcstatus.AuthorizePolicyName) *policygrpc.CryptoPolicyHandler {
	t.Helper()
	h, err := policygrpc.New(context.Background(), newPolicy, authorizePolicy)
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

// ============================================================================
// ListAllowedAlgorithms
// ============================================================================

// signatureFilter is a ListAllowedAlgorithms filter on the standard signature
// scope.
func signatureFilter() *typespb.ScopeSpecification {
	return &typespb.ScopeSpecification{
		ScopeSpec: &typespb.ScopeSpecification_Signature{
			Signature: &typespb.SignatureScopeSpec{Scope: typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD},
		},
	}
}

// failOnEngine is a policy engine factory that fails the test if the handler
// reaches the engine.
func failOnEngine(t *testing.T) policy.EngineFactory {
	return func(_ context.Context) (policy.Engine, error) {
		t.Error("policy engine factory must not be called")
		return &mockPolicyManager{}, nil
	}
}

func allowAllPolicies(_ context.Context, _ engerr.Op, _ string) error { return nil }

func TestCryptoPolicyHandler_ListAllowedAlgorithms_WithFilters_Success(t *testing.T) {
	ctx := context.Background()
	allowed := []string{"ecdsa-p256-sha256-der", "ml-dsa-65"}
	pm := &mockPolicyManager{
		allowedTemplatesFn: func(_ context.Context, policyName string, scopeSpec *core.ScopeSpecification) ([]string, error) {
			if policyName != "tenant-a/strict" {
				t.Errorf("policy name: got %q want tenant-a/strict", policyName)
			}
			if scopeSpec == nil {
				t.Fatal("expected the filters to be converted to a scope specification")
			}
			if scopeSpec.Scope != core.ScopeSignatureStandard {
				t.Errorf("scope: got %q want %q", scopeSpec.Scope, core.ScopeSignatureStandard)
			}
			return allowed, nil
		},
	}
	h := wirePolicy(t, pm)

	resp, err := h.ListAllowedAlgorithms(ctx, &messagespb.ListAllowedAlgorithmsRequest{
		PolicyName: "tenant-a/strict",
		Filters:    signatureFilter(),
	})
	if err != nil {
		t.Fatalf("ListAllowedAlgorithms: %v", err)
	}
	if resp.GetPolicyName() != "tenant-a/strict" {
		t.Errorf("policy_name: got %q", resp.GetPolicyName())
	}
	if resp.GetPolicyVersion() != -1 {
		t.Errorf("policy_version: got %d want -1 (not supported yet)", resp.GetPolicyVersion())
	}
	if !slices.Equal(resp.GetAllowedTemplates(), allowed) {
		t.Errorf("allowed_templates: got %v want %v", resp.GetAllowedTemplates(), allowed)
	}
	if len(resp.GetLegacyTemplates()) != 0 {
		t.Errorf("legacy_templates: expected none, got %v", resp.GetLegacyTemplates())
	}
}

func TestCryptoPolicyHandler_ListAllowedAlgorithms_NoFilters_PassesNilScope(t *testing.T) {
	ctx := context.Background()
	allowed := []string{"ml-dsa-65"}
	pm := &mockPolicyManager{
		allowedTemplatesFn: func(_ context.Context, _ string, scopeSpec *core.ScopeSpecification) ([]string, error) {
			if scopeSpec != nil {
				t.Errorf("expected nil scope specification without filters, got %+v", scopeSpec)
			}
			return allowed, nil
		},
	}
	h := wirePolicy(t, pm)

	resp, err := h.ListAllowedAlgorithms(ctx, &messagespb.ListAllowedAlgorithmsRequest{PolicyName: "tenant-a/strict"})
	if err != nil {
		t.Fatalf("ListAllowedAlgorithms: %v", err)
	}
	if !slices.Equal(resp.GetAllowedTemplates(), allowed) {
		t.Errorf("allowed_templates: got %v want %v", resp.GetAllowedTemplates(), allowed)
	}
}

// A policy without an allowed-templates section allows nothing (deny by
// default): an empty list, not an error.
func TestCryptoPolicyHandler_ListAllowedAlgorithms_NothingAllowed_ReturnsEmptyList(t *testing.T) {
	ctx := context.Background()
	pm := &mockPolicyManager{
		allowedTemplatesFn: func(_ context.Context, _ string, _ *core.ScopeSpecification) ([]string, error) {
			return []string{}, nil
		},
	}
	h := wirePolicy(t, pm)

	resp, err := h.ListAllowedAlgorithms(ctx, &messagespb.ListAllowedAlgorithmsRequest{PolicyName: "deny-all"})
	if err != nil {
		t.Fatalf("ListAllowedAlgorithms: %v", err)
	}
	if len(resp.GetAllowedTemplates()) != 0 {
		t.Errorf("allowed_templates: expected none, got %v", resp.GetAllowedTemplates())
	}
	if resp.GetPolicyName() != "deny-all" {
		t.Errorf("policy_name: got %q", resp.GetPolicyName())
	}
}

func TestCryptoPolicyHandler_ListAllowedAlgorithms_EmptyPolicyName_ReturnsInvalidArgument(t *testing.T) {
	authorize := func(_ context.Context, _ engerr.Op, _ string) error {
		t.Error("policy authorization must not be called for an empty name")
		return nil
	}
	h := wirePolicyFactory(t, failOnEngine(t), authorize)

	_, err := h.ListAllowedAlgorithms(context.Background(), &messagespb.ListAllowedAlgorithmsRequest{
		PolicyName: "",
		Filters:    signatureFilter(),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", status.Code(err))
	}
}

func TestCryptoPolicyHandler_ListAllowedAlgorithms_NotAuthorized_ReturnsPermissionDenied(t *testing.T) {
	var authorized string
	authorize := func(ctx context.Context, op engerr.Op, name string) error {
		authorized = name
		return engerr.New(ctx, op, engerr.CodePolicyViolation, "caller may not read policy "+name)
	}
	h := wirePolicyFactory(t, failOnEngine(t), authorize)

	_, err := h.ListAllowedAlgorithms(context.Background(), &messagespb.ListAllowedAlgorithmsRequest{PolicyName: "tenant-a/strict"})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", status.Code(err))
	}
	if authorized != "tenant-a/strict" {
		t.Errorf("policy authorization: got name %q want tenant-a/strict", authorized)
	}
}

func TestCryptoPolicyHandler_ListAllowedAlgorithms_InvalidFilters_ReturnsInvalidArgument(t *testing.T) {
	tests := []struct {
		name    string
		filters *typespb.ScopeSpecification
	}{
		{"no scope family set", &typespb.ScopeSpecification{}},
		{"unrecognized scope", &typespb.ScopeSpecification{
			ScopeSpec: &typespb.ScopeSpecification_Signature{
				Signature: &typespb.SignatureScopeSpec{Scope: typespb.SignatureScope_SIGNATURE_SCOPE_UNSPECIFIED},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &mockPolicyManager{} // AllowedTemplates panics if reached
			h := wirePolicy(t, pm)

			_, err := h.ListAllowedAlgorithms(context.Background(), &messagespb.ListAllowedAlgorithmsRequest{
				PolicyName: "tenant-a/strict",
				Filters:    tt.filters,
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("expected InvalidArgument, got %v", status.Code(err))
			}
		})
	}
}

func TestCryptoPolicyHandler_ListAllowedAlgorithms_EngineError_MapsToStatus(t *testing.T) {
	tests := []struct {
		name string
		code engerr.Code
		want codes.Code
	}{
		{"policy not found", engerr.CodePolicyNotFound, codes.NotFound},
		{"malformed policy document", engerr.CodeInternal, codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &mockPolicyManager{
				allowedTemplatesFn: func(ctx context.Context, _ string, _ *core.ScopeSpecification) ([]string, error) {
					return nil, engerr.New(ctx, "test", tt.code, tt.name)
				},
			}
			h := wirePolicy(t, pm)

			_, err := h.ListAllowedAlgorithms(context.Background(), &messagespb.ListAllowedAlgorithmsRequest{PolicyName: "tenant-a/strict"})
			if status.Code(err) != tt.want {
				t.Errorf("expected %v, got %v", tt.want, status.Code(err))
			}
		})
	}
}

func TestCryptoPolicyHandler_ListAllowedAlgorithms_EngineFactoryError_MapsToStatus(t *testing.T) {
	newPolicy := policy.EngineFactory(func(ctx context.Context) (policy.Engine, error) {
		return nil, engerr.New(ctx, "test", engerr.CodeInternal, "policy store unavailable")
	})
	h := wirePolicyFactory(t, newPolicy, allowAllPolicies)

	_, err := h.ListAllowedAlgorithms(context.Background(), &messagespb.ListAllowedAlgorithmsRequest{PolicyName: "tenant-a/strict"})
	if status.Code(err) != codes.Internal {
		t.Errorf("expected Internal, got %v", status.Code(err))
	}
}
