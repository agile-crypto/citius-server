package grpc_test

import (
	"context"
	"testing"

	typespb "github.com/agile-crypto/citius-server/gen/go/api/types"
	"github.com/stretchr/testify/require"

	messagespb "github.com/agile-crypto/citius-server/gen/go/api/messages"
	"github.com/agile-crypto/citius-server/internal/core"
	"github.com/agile-crypto/citius-server/internal/crypto"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
	grpchandler "github.com/agile-crypto/citius-server/internal/grpc"
	"github.com/agile-crypto/citius-server/internal/key"
	"github.com/agile-crypto/citius-server/internal/policy"
	"github.com/agile-crypto/citius-server/internal/service"
	"github.com/agile-crypto/citius-server/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ============================================================================
// Mock types
// ============================================================================

// mockScope implements the grpchandler.scopeGateway interface (Keys + Crypto + Policy).
// We rely on the package-private interface being satisfied via duck-typing.
type mockScope struct {
	keys   service.KeyOrchestrator
	crypto service.CryptoOrchestrator
	policy policy.Engine
}

func (s *mockScope) Keys() service.KeyOrchestrator      { return s.keys }
func (s *mockScope) Crypto() service.CryptoOrchestrator { return s.crypto }
func (s *mockScope) Policy() policy.Engine              { return s.policy }

// mockSvc implements the grpchandler.serviceGateway interface (ForStorage).
// It returns the pre-built scope without touching storage.
type mockSvc struct{ scope *mockScope }

func (s *mockSvc) ForStorage(_ context.Context, _ storage.Storage) (grpchandler.ScopeGateway, error) {
	return s.scope, nil
}

var _ grpchandler.ServiceGateway = (*mockSvc)(nil) // compile-time check
var _ grpchandler.ScopeGateway = (*mockScope)(nil) // compile-time check

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

// mockKeyOrchestrator stubs KeyOrchestrator for tests.
// Only createFn and readFn are wired; all other methods panic.
type mockKeyOrchestrator struct {
	createFn             func(ctx context.Context, spec core.KeyCreationSpec) (*service.KeyMetadata, error)
	readFn               func(ctx context.Context, name string) (*service.KeyMetadata, error)
	getKeyWithMaterialFn func(ctx context.Context, name string, version uint32) (*key.Key, *key.Version, error)
	transformFn          func(ctx context.Context, spec service.TransformKeySpec) (*service.KeyMetadata, error)
}

func (m *mockKeyOrchestrator) CreateKey(ctx context.Context, spec core.KeyCreationSpec) (*service.KeyMetadata, error) {
	if m.createFn != nil {
		return m.createFn(ctx, spec)
	}
	panic("mockKeyOrchestrator.CreateKey: not implemented")
}

func (m *mockKeyOrchestrator) ReadKey(ctx context.Context, name string, version uint32) (*service.KeyMetadata, error) {
	if m.readFn != nil {
		return m.readFn(ctx, name)
	}
	panic("mockKeyOrchestrator.ReadKey: not implemented")
}

// Stub the rest of the interface.
func (m *mockKeyOrchestrator) ListKeys(_ context.Context) ([]*service.KeyMetadata, error) {
	panic("mockKeyOrchestrator.ListKeys: not implemented")
}
func (m *mockKeyOrchestrator) DeleteKey(_ context.Context, _ string) error {
	panic("mockKeyOrchestrator.DeleteKey: not implemented")
}
func (m *mockKeyOrchestrator) GetKeyWithMaterial(ctx context.Context, name string, version uint32) (*key.Key, *key.Version, error) {
	if m.getKeyWithMaterialFn != nil {
		return m.getKeyWithMaterialFn(ctx, name, version)
	}
	panic("mockKeyOrchestrator.GetKeyWithMaterial: not implemented")
}
func (m *mockKeyOrchestrator) RotateKey(_ context.Context, _ string) (*service.KeyMetadata, error) {
	panic("mockKeyOrchestrator.RotateKey: not implemented")
}
func (m *mockKeyOrchestrator) SuspendKey(_ context.Context, _ string) error {
	panic("mockKeyOrchestrator.SuspendKey: not implemented")
}
func (m *mockKeyOrchestrator) RestoreKey(_ context.Context, _ string) error {
	panic("mockKeyOrchestrator.RestoreKey: not implemented")
}
func (m *mockKeyOrchestrator) DestroyKey(_ context.Context, _ string) error {
	panic("mockKeyOrchestrator.DestroyKey: not implemented")
}
func (m *mockKeyOrchestrator) ImportKey(_ context.Context, _ core.ImportKeySpec) (*service.KeyMetadata, error) {
	panic("mockKeyOrchestrator.ImportKey: not implemented")
}
func (m *mockKeyOrchestrator) UpdateKeyPolicy(_ context.Context, _ string, _ string) error {
	panic("mockKeyOrchestrator.UpdateKeyPolicy: not implemented")
}

func (m *mockKeyOrchestrator) TransformKey(ctx context.Context, spec service.TransformKeySpec) (*service.KeyMetadata, error) {
	if m.transformFn != nil {
		return m.transformFn(ctx, spec)
	}
	panic("mockKeyOrchestrator.TransformKey: not implemented")
}

// mockCryptoOps stubs CryptoOrchestrator for tests.
// Only signFn and verifyFn are wired; all other methods panic.
type mockCryptoOps struct {
	signFn   func(ctx context.Context, req crypto.SignRequest) (crypto.SignResult, error)
	verifyFn func(ctx context.Context, req crypto.VerifyRequest) (crypto.VerifyResult, error)
}

func (m *mockCryptoOps) Sign(ctx context.Context, req crypto.SignRequest) (crypto.SignResult, error) {
	if m.signFn != nil {
		return m.signFn(ctx, req)
	}
	panic("mockCryptoOps.Sign: not implemented")
}

func (m *mockCryptoOps) Verify(ctx context.Context, req crypto.VerifyRequest) (crypto.VerifyResult, error) {
	if m.verifyFn != nil {
		return m.verifyFn(ctx, req)
	}
	panic("mockCryptoOps.Verify: not implemented")
}

// Stub the rest of the interface.
func (m *mockCryptoOps) Encrypt(_ context.Context, _ crypto.EncryptRequest) (crypto.EncryptResult, error) {
	panic("mockCryptoOps.Encrypt: not implemented")
}
func (m *mockCryptoOps) Decrypt(_ context.Context, _ crypto.DecryptRequest) (crypto.DecryptResult, error) {
	panic("mockCryptoOps.Decrypt: not implemented")
}
func (m *mockCryptoOps) WrapKey(_ context.Context, _ crypto.WrapKeyRequest) (crypto.WrapKeyResult, error) {
	panic("mockCryptoOps.WrapKey: not implemented")
}
func (m *mockCryptoOps) UnwrapKey(_ context.Context, _ crypto.UnwrapKeyRequest) (crypto.UnwrapKeyResult, error) {
	panic("mockCryptoOps.UnwrapKey: not implemented")
}
func (m *mockCryptoOps) DeriveKey(_ context.Context, _ crypto.DeriveKeyRequest) (*key.Key, error) {
	panic("mockCryptoOps.DeriveKey: not implemented")
}
func (m *mockCryptoOps) GenerateMAC(_ context.Context, _ crypto.MacRequest) (crypto.MacResult, error) {
	panic("mockCryptoOps.GenerateMAC: not implemented")
}
func (m *mockCryptoOps) VerifyMAC(_ context.Context, _ crypto.VerifyMacRequest) (crypto.VerifyMacResult, error) {
	panic("mockCryptoOps.VerifyMAC: not implemented")
}
func (m *mockCryptoOps) Digest(_ context.Context, _ crypto.DigestRequest) (crypto.DigestResult, error) {
	panic("mockCryptoOps.Digest: not implemented")
}
func (m *mockCryptoOps) GenerateRandom(_ context.Context, _ int) ([]byte, error) {
	panic("mockCryptoOps.GenerateRandom: not implemented")
}

// ============================================================================
// Helper
// ============================================================================

func wireHandler(keys service.KeyOrchestrator, cr service.CryptoOrchestrator) *grpchandler.Handler {
	return wireHandlerWithPolicy(keys, cr, nil)
}

func wireHandlerWithPolicy(keys service.KeyOrchestrator, cr service.CryptoOrchestrator, pm policy.Engine) *grpchandler.Handler {
	svc := &mockSvc{scope: &mockScope{keys: keys, crypto: cr, policy: pm}}
	return grpchandler.New(svc, nil)
}

// ============================================================================
// Tests
// ============================================================================

func TestHandler_CreateKey_Success(t *testing.T) {
	ctx := context.Background()
	km := &mockKeyOrchestrator{
		createFn: func(_ context.Context, spec core.KeyCreationSpec) (*service.KeyMetadata, error) {
			if spec.Name == "" {
				t.Error("expected non-empty name in CreateKey spec")
			}
			if spec.TemplateID != "ecdsa-p256-sha256-der" {
				t.Errorf("expected template ecdsa-p256-sha256-der, got %s", spec.TemplateID)
			}
			return &service.KeyMetadata{
				Name:       spec.Name,
				KeyID:      spec.Name,
				Version:    1,
				TemplateID: "ecdsa-p256-sha256-der",
				Provider:   "software",
			}, nil
		},
	}
	h := wireHandler(km, nil)

	templateID := "ecdsa-p256-sha256-der"
	resp, err := h.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name: "my-key",
		ScopeSpec: &typespb.ScopeSpecification{
			ScopeSpec: &typespb.ScopeSpecification_Signature{
				Signature: &typespb.SignatureScopeSpec{
					Scope: typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD,
				},
			},
		},
		TemplateId: &templateID,
	})
	if err != nil {
		t.Fatalf("CreateKey handler: %v", err)
	}
	if resp.GetKeyMetadata().GetName() != "my-key" {
		t.Errorf("expected key name my-key, got %s", resp.GetKeyMetadata().GetName())
	}
	if !resp.GetSuccess() {
		t.Error("expected Success: true in CreateKeyResponse")
	}
}

func TestHandler_CreateKey_ValidationError_ReturnsInvalidArgument(t *testing.T) {
	ctx := context.Background()
	km := &mockKeyOrchestrator{
		createFn: func(ctx context.Context, _ core.KeyCreationSpec) (*service.KeyMetadata, error) {
			return nil, engerr.New(ctx, "test", engerr.CodeInvalidArgument, "name required")
		},
	}
	h := wireHandler(km, nil)

	_, err := h.CreateKey(ctx, &messagespb.CreateKeyRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %s", st.Code())
	}
}

func TestHandler_ReadKey_NotFound_ReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	km := &mockKeyOrchestrator{
		readFn: func(ctx context.Context, name string) (*service.KeyMetadata, error) {
			return nil, engerr.New(ctx, "test", engerr.CodeKeyNotFound, "key not found")
		},
	}
	h := wireHandler(km, nil)

	_, err := h.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: "nonexistent"})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %s", st.Code())
	}
}

func TestHandler_Sign_Success(t *testing.T) {
	ctx := context.Background()
	providerOutput := &messagespb.ProviderOutput{
		AlgorithmOutput: &messagespb.ProviderOutput_NoOutput{
			NoOutput: &messagespb.NoAlgorithmOutput{},
		},
		Encoding: "raw",
	}
	cr := &mockCryptoOps{
		signFn: func(_ context.Context, req crypto.SignRequest) (crypto.SignResult, error) {
			if req.NoContext == nil {
				t.Error("expected NoContext to be set for ECDSA sign")
			}
			return crypto.SignResult{
				Signature:    []byte("fake-sig"),
				KeyName:      req.KeyName,
				Algorithm:    "ecdsa-p256-sha256-der",
				ProviderName: "software",
				Output:       providerOutput,
			}, nil
		},
	}
	h := wireHandler(nil, cr)

	resp, err := h.Sign(ctx, &messagespb.SignRequest{
		KeyName: "key_123",
		Input:   []byte("hello"),
		ScopeParams: &messagespb.SignRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("Sign handler: %v", err)
	}
	if len(resp.GetSignature()) == 0 {
		t.Error("Sign response: empty signature")
	}
	if resp.GetMetadata() == nil {
		t.Fatal("Sign response: Metadata must not be nil")
	}
	if resp.GetMetadata().GetProviderOutput() == nil {
		t.Error("Sign response: Metadata.ProviderOutput must not be nil")
	}
}

func TestHandler_Verify_InvalidSig_ReturnsValidFalse(t *testing.T) {
	ctx := context.Background()
	cr := &mockCryptoOps{
		verifyFn: func(_ context.Context, req crypto.VerifyRequest) (crypto.VerifyResult, error) {
			if req.NoContext == nil {
				t.Error("expected NoContext to be set for ECDSA verify")
			}
			return crypto.VerifyResult{Valid: false}, nil // invalid sig — not an error
		},
	}
	h := wireHandler(nil, cr)

	resp, err := h.Verify(ctx, &messagespb.VerifyRequest{
		KeyName:   "key_123",
		Input:     []byte("hello"),
		Signature: []byte("bad-sig"),
		ScopeParams: &messagespb.VerifyRequest_NoContext{
			NoContext: &typespb.NoParams{},
		},
	})
	if err != nil {
		t.Fatalf("Verify handler should not error for invalid sig: %v", err)
	}
	if resp.GetValid() {
		t.Error("Verify response: expected valid=false")
	}
}

func TestHandler_TransformKey_Success(t *testing.T) {
	ctx := context.Background()
	km := &mockKeyOrchestrator{
		transformFn: func(_ context.Context, spec service.TransformKeySpec) (*service.KeyMetadata, error) {
			if spec.KeyName == "" {
				t.Error("expected non-empty key name in TransformKey spec")
			}
			return &service.KeyMetadata{
				Name:       spec.KeyName,
				KeyID:      spec.KeyName,
				Version:    1,
				TemplateID: "ecdsa-p256-sha256-der",
				Provider:   "software",
			}, nil
		},
	}
	h := wireHandler(km, nil)

	resp, err := h.TransformKey(ctx, &messagespb.TransformKeyRequest{
		Name: "key_123",
		ScopeSpec: &typespb.ScopeSpecification{
			ScopeSpec: &typespb.ScopeSpecification_Signature{
				Signature: &typespb.SignatureScopeSpec{
					Scope: typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("TransformKey handler: %v", err)
	}
	md := resp.GetKeyMetadata()
	require.Equal(t, "key_123", md.GetName())
	require.Equal(t, "ecdsa-p256-sha256-der", md.GetTemplateId())
	require.True(t, resp.GetSuccess())
	require.Equal(t, "key_123", md.KeyId)
	require.Equal(t, "software", md.Provider)
	require.Equal(t, uint32(1), md.Version)
}

func TestHandler_TransformKey_WithErrors(t *testing.T) {
	ctx := context.Background()
	km := &mockKeyOrchestrator{
		transformFn: func(_ context.Context, spec service.TransformKeySpec) (*service.KeyMetadata, error) {
			return nil, engerr.New(ctx, "test", engerr.CodeInvalidArgument, "name required")
		},
	}
	h := wireHandler(km, nil)

	_, err := h.TransformKey(ctx, &messagespb.TransformKeyRequest{})
	require.NotNil(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code())
}
