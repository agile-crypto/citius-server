// Tests replicated from the monolithic internal/grpc handler suite, so that
// each service handler is covered where it now lives. The assertions are
// unchanged; only the wiring differs — the handler is built from a factory
// closure over the mock instead of a ServiceGateway/scope pair.

package keygrpc_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-server/internal/core"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
	keygrpc "github.com/agile-crypto/citius-server/internal/grpc/keymanagement"
	"github.com/agile-crypto/citius-server/internal/key"
	"github.com/agile-crypto/citius-server/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

// wireKeys builds the handler under test over a fixed orchestrator. The factory
// ignores its context and returns the same mock every call, which is exactly
// what a startup-wired (SQL or embedded) deployment does.
func wireKeys(t *testing.T, keys service.KeyOrchestrator) *keygrpc.KeyManagementHandler {
	t.Helper()
	newKeys := service.KeyOrchestratorFactory(func(_ context.Context) (service.KeyOrchestrator, error) {
		return keys, nil
	})
	authFn := func(ctx context.Context, op engerr.Op, name string) error {
		return nil
	}
	h, err := keygrpc.New(context.Background(), newKeys, authFn, authFn)
	if err != nil {
		t.Fatalf("keygrpc.New: %v", err)
	}
	return h
}

func TestKeyManagementHandler_CreateKey_Success(t *testing.T) {
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
	h := wireKeys(t, km)

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

func TestKeyManagementHandler_CreateKey_ValidationError_ReturnsInvalidArgument(t *testing.T) {
	ctx := context.Background()
	km := &mockKeyOrchestrator{
		createFn: func(ctx context.Context, _ core.KeyCreationSpec) (*service.KeyMetadata, error) {
			return nil, engerr.New(ctx, "test", engerr.CodeInvalidArgument, "name required")
		},
	}
	h := wireKeys(t, km)

	_, err := h.CreateKey(ctx, &messagespb.CreateKeyRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %s", st.Code())
	}
}

func TestKeyManagementHandler_ReadKey_NotFound_ReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	km := &mockKeyOrchestrator{
		readFn: func(ctx context.Context, name string) (*service.KeyMetadata, error) {
			return nil, engerr.New(ctx, "test", engerr.CodeKeyNotFound, "key not found")
		},
	}
	h := wireKeys(t, km)

	_, err := h.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: "nonexistent"})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %s", st.Code())
	}
}

func TestKeyManagementHandler_TransformKey_Success(t *testing.T) {
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
	h := wireKeys(t, km)

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

func TestKeyManagementHandler_TransformKey_WithErrors(t *testing.T) {
	ctx := context.Background()
	km := &mockKeyOrchestrator{
		transformFn: func(_ context.Context, spec service.TransformKeySpec) (*service.KeyMetadata, error) {
			return nil, engerr.New(ctx, "test", engerr.CodeInvalidArgument, "name required")
		},
	}
	h := wireKeys(t, km)

	_, err := h.TransformKey(ctx, &messagespb.TransformKeyRequest{})
	require.NotNil(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code())
}
