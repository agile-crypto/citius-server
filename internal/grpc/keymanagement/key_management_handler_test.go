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
	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-core/service"
	keygrpc "github.com/agile-crypto/citius-server/internal/grpc/keymanagement"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// mockKeyOrchestrator stubs KeyOrchestrator for tests.
// Only createFn and readFn are wired; all other methods panic.
type mockKeyOrchestrator struct {
	createFn             func(ctx context.Context, spec core.KeyCreationSpec) (*service.KeyMetadata, error)
	readFn               func(ctx context.Context, name string) (*service.KeyMetadata, error)
	getKeyWithMaterialFn func(ctx context.Context, name string, version uint32) (*key.Key, *key.Version, error)
	transformFn          func(ctx context.Context, spec service.TransformKeySpec) (*service.KeyMetadata, error)
	migrateFn            func(ctx context.Context, spec service.MigrateKeySpec) (*service.MigrationResult, error)
	validateMigrationFn  func(ctx context.Context, spec service.MigrateKeySpec) (*service.MigrationValidation, error)
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

func (m *mockKeyOrchestrator) MigrateKey(ctx context.Context, spec service.MigrateKeySpec) (*service.MigrationResult, error) {
	if m.migrateFn != nil {
		return m.migrateFn(ctx, spec)
	}
	panic("mockKeyOrchestrator.MigrateKey: not implemented")
}

func (m *mockKeyOrchestrator) ValidateMigration(ctx context.Context, spec service.MigrateKeySpec) (*service.MigrationValidation, error) {
	if m.validateMigrationFn != nil {
		return m.validateMigrationFn(ctx, spec)
	}
	panic("mockKeyOrchestrator.ValidateMigration: not implemented")
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
				ScopeSpec:  &core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
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
	require.Equal(t, typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD, resp.GetKeyMetadata().GetScopeSpec().GetSignature().GetScope())
}

func TestKeyManagementHandler_CreateKey_MapsProviderRequirements(t *testing.T) {
	ctx := context.Background()
	var got core.ProviderRequirements
	km := &mockKeyOrchestrator{
		createFn: func(_ context.Context, spec core.KeyCreationSpec) (*service.KeyMetadata, error) {
			got = spec.ProviderRequirements
			return &service.KeyMetadata{Name: spec.Name, Version: 1}, nil
		},
	}
	h := wireKeys(t, km)

	_, err := h.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name: "my-key",
		ProviderRequirements: &typespb.ProviderRequirements{
			Fips_140Certified:         proto.Bool(true),
			MinFipsLevel:              typespb.Fips140Level_FIPS_140_LEVEL_1,
			PreferHardwareAccelerated: proto.Bool(true),
		},
	})
	require.NoError(t, err)
	require.Equal(t, core.ProviderRequirements{FIPS140Certified: true, MinFIPS140Level: 1, PreferHardwareAccelerated: true}, got)
}

func TestKeyManagementHandler_CreateKey_UnenforceableProviderRequirements_ReturnsInvalidArgument(t *testing.T) {
	h := wireKeys(t, &mockKeyOrchestrator{}) // CreateKey must not be reached

	_, err := h.CreateKey(context.Background(), &messagespb.CreateKeyRequest{
		Name:                 "my-key",
		ProviderRequirements: &typespb.ProviderRequirements{Additional: map[string]string{"vendor": "acme"}},
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
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

func TestKeyManagementHandler_ReadKey_PreservesScopeMetadata(t *testing.T) {
	ctx := context.Background()
	km := &mockKeyOrchestrator{
		readFn: func(_ context.Context, _ string) (*service.KeyMetadata, error) {
			return &service.KeyMetadata{
				Name:       "my-key",
				KeyID:      "key_123",
				Version:    2,
				TemplateID: "ml-dsa-65",
				Provider:   "software",
				ScopeSpec:  &core.ScopeSpecification{Scope: core.ScopeSignatureStandard},
			}, nil
		},
	}
	h := wireKeys(t, km)

	version := uint32(2)
	resp, err := h.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: "my-key", Version: &version})
	require.NoError(t, err)
	require.Equal(t, uint32(2), resp.GetKeyMetadata().GetVersion())
	require.Equal(t, typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD, resp.GetKeyMetadata().GetScopeSpec().GetSignature().GetScope())
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

func TestKeyManagementHandler_MigrateKey_Success(t *testing.T) {
	ctx := context.Background()
	strategy := messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE
	km := &mockKeyOrchestrator{
		migrateFn: func(_ context.Context, spec service.MigrateKeySpec) (*service.MigrationResult, error) {
			require.Equal(t, service.MigrateKeySpec{KeyName: "key_123", TargetInstanceID: "openssl", Strategy: strategy}, spec)
			return &service.MigrationResult{
				Key: &service.KeyMetadata{
					Name: spec.KeyName, KeyID: "key-id", Version: 2,
					TemplateID: "ecdsa-p256-sha256-der", Provider: "openssl",
				},
				Strategy:         strategy,
				SourceProviderID: "software",
				SourceInstanceID: "software",
				SourceVersion:    1,
				TargetProviderID: "openssl",
				TargetInstanceID: "openssl",
			}, nil
		},
	}
	h := wireKeys(t, km)

	resp, err := h.MigrateKey(ctx, &messagespb.MigrateKeyRequest{
		Name:     "key_123",
		Target:   &messagespb.MigrateKeyRequest_TargetInstanceId{TargetInstanceId: "openssl"},
		Strategy: strategy,
	})
	require.NoError(t, err)
	require.True(t, resp.GetSuccess())
	require.Equal(t, uint32(2), resp.GetKeyMetadata().GetVersion())
	require.Equal(t, "openssl", resp.GetKeyMetadata().GetProvider())
	require.Equal(t, strategy, resp.GetResult().GetStrategyUsed())
	require.False(t, resp.GetResult().GetKeyBytesPreserved())
	require.Equal(t, "software", resp.GetResult().GetSourceInstanceId())
	require.Equal(t, "openssl", resp.GetResult().GetTargetInstanceId())
	require.Equal(t, "key_123", resp.GetArchivedKeyInfo().GetArchivedKeyName())
	require.Equal(t, "software", resp.GetArchivedKeyInfo().GetProviderId())
}

func TestKeyManagementHandler_MigrateKey_Errors(t *testing.T) {
	ctx := context.Background()
	templateID := "ecdsa-p256-sha256-der"
	tests := []struct {
		name     string
		req      *messagespb.MigrateKeyRequest
		migrate  func(context.Context, service.MigrateKeySpec) (*service.MigrationResult, error)
		wantCode codes.Code
	}{
		{
			name:     "template change is refused before the orchestrator",
			req:      &messagespb.MigrateKeyRequest{Name: "key_123", TemplateId: &templateID},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "orchestrator error is mapped",
			req: &messagespb.MigrateKeyRequest{
				Name:     "key_123",
				Target:   &messagespb.MigrateKeyRequest_TargetInstanceId{TargetInstanceId: "software"},
				Strategy: messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
			},
			migrate: func(ctx context.Context, _ service.MigrateKeySpec) (*service.MigrationResult, error) {
				return nil, engerr.New(ctx, "test", engerr.CodeFailedPrecondition, "already on provider instance")
			},
			wantCode: codes.FailedPrecondition,
		},
		{
			name: "unimplemented strategy",
			req: &messagespb.MigrateKeyRequest{
				Name:     "key_123",
				Target:   &messagespb.MigrateKeyRequest_TargetInstanceId{TargetInstanceId: "openssl"},
				Strategy: messagespb.MigrationStrategy_MIGRATION_STRATEGY_WRAPPED_TRANSFER,
			},
			migrate: func(ctx context.Context, _ service.MigrateKeySpec) (*service.MigrationResult, error) {
				return nil, engerr.New(ctx, "test", engerr.CodeNotImplemented, "not implemented")
			},
			wantCode: codes.Unimplemented,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := wireKeys(t, &mockKeyOrchestrator{migrateFn: tt.migrate})
			_, err := h.MigrateKey(ctx, tt.req)
			require.Equal(t, tt.wantCode, status.Code(err), "%v", err)
		})
	}
}

func TestKeyManagementHandler_ValidateKeyOperation_Migrate(t *testing.T) {
	ctx := context.Background()
	strategy := messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH
	km := &mockKeyOrchestrator{
		validateMigrationFn: func(_ context.Context, spec service.MigrateKeySpec) (*service.MigrationValidation, error) {
			require.Equal(t, service.MigrateKeySpec{KeyName: "key_123", TargetProviderID: "openssl", Strategy: strategy}, spec)
			return &service.MigrationValidation{
				TemplateID:       "ecdsa-p256-sha256-der",
				SourceProviderID: "software",
				SourceInstanceID: "software",
				Extractable:      true,
				Options: []service.StrategyAssessment{
					{Strategy: strategy, Feasible: true, TargetInstanceID: "openssl", SecurityNotes: []string{"note"}},
				},
				Recommended:          strategy,
				RecommendationReason: "reason",
			}, nil
		},
	}
	h := wireKeys(t, km)

	resp, err := h.ValidateKeyOperation(ctx, &messagespb.ValidateKeyOperationRequest{
		Name: "key_123",
		Intent: &messagespb.ValidateKeyOperationRequest_Migrate{Migrate: &messagespb.ValidateMigrateIntent{
			Target:            &messagespb.ValidateMigrateIntent_TargetProviderId{TargetProviderId: "openssl"},
			PreferredStrategy: strategy,
		}},
	})
	require.NoError(t, err)
	require.Equal(t, "software", resp.GetCurrentState().GetInstanceId())
	require.True(t, resp.GetCurrentState().GetExtractable())
	require.Len(t, resp.GetOptions(), 1)
	require.True(t, resp.GetOptions()[0].GetFeasible())
	require.Equal(t, []string{"note"}, resp.GetOptions()[0].GetSecurityNotes())
	require.Equal(t, strategy, resp.GetRecommendedStrategy())
	require.Equal(t, "reason", resp.GetRecommendationReason())
}

func TestKeyManagementHandler_ValidateKeyOperation_Errors(t *testing.T) {
	ctx := context.Background()
	migrate := &messagespb.ValidateKeyOperationRequest_Migrate{Migrate: &messagespb.ValidateMigrateIntent{
		Target: &messagespb.ValidateMigrateIntent_TargetInstanceId{TargetInstanceId: "openssl"},
	}}
	tests := []struct {
		name     string
		req      *messagespb.ValidateKeyOperationRequest
		validate func(context.Context, service.MigrateKeySpec) (*service.MigrationValidation, error)
		wantCode codes.Code
	}{
		{
			name:     "no intent",
			req:      &messagespb.ValidateKeyOperationRequest{Name: "key_123"},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "transform intent",
			req: &messagespb.ValidateKeyOperationRequest{Name: "key_123",
				Intent: &messagespb.ValidateKeyOperationRequest_Transform{Transform: &messagespb.ValidateTransformIntent{}}},
			wantCode: codes.Unimplemented,
		},
		{
			name: "migrate intent without a target is refused by the orchestrator",
			req:  &messagespb.ValidateKeyOperationRequest{Name: "key_123", Intent: &messagespb.ValidateKeyOperationRequest_Migrate{}},
			validate: func(ctx context.Context, spec service.MigrateKeySpec) (*service.MigrationValidation, error) {
				require.Equal(t, service.MigrateKeySpec{KeyName: "key_123"}, spec)
				return nil, engerr.New(ctx, "test", engerr.CodeInvalidArgument, "exactly one target")
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "no validation is an internal error",
			req:  &messagespb.ValidateKeyOperationRequest{Name: "key_123", Intent: migrate},
			validate: func(context.Context, service.MigrateKeySpec) (*service.MigrationValidation, error) {
				return nil, nil
			},
			wantCode: codes.Internal,
		},
		{
			name: "orchestrator error is mapped",
			req:  &messagespb.ValidateKeyOperationRequest{Name: "nope", Intent: migrate},
			validate: func(ctx context.Context, _ service.MigrateKeySpec) (*service.MigrationValidation, error) {
				return nil, engerr.New(ctx, "test", engerr.CodeKeyNotFound, "key not found")
			},
			wantCode: codes.NotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := wireKeys(t, &mockKeyOrchestrator{validateMigrationFn: tt.validate})
			_, err := h.ValidateKeyOperation(ctx, tt.req)
			require.Equal(t, tt.wantCode, status.Code(err))
		})
	}
}
