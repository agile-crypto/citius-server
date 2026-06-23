package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	types "github.ibm.com/citius/citius-server/gen/go/api/types"
	providerpb "github.ibm.com/citius/citius-server/gen/go/server/provider"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/template"
)

// ============================================================================
// NewKeyOrchestrator Constructor Tests
// ============================================================================

// allDeps creates a full set of valid dependencies for the constructor.
func allDeps(t *testing.T) (key.Repository, template.Registry, provider.Registry, policy.Engine) {
	t.Helper()
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	repo, err := key.NewVaultRepository(ctx, storage)
	if err != nil {
		t.Fatalf("NewVaultRepository: %v", err)
	}
	reg, err := template.NewVaultRegistry(ctx, storage)
	if err != nil {
		t.Fatalf("NewVaultRegistry: %v", err)
	}
	prov := provider.NewRegistry()
	policyRepo, err := policy.NewVaultRepository(ctx, storage)
	if err != nil {
		t.Fatalf("policy.NewVaultRepository: %v", err)
	}
	eval := policy.NewSimpleRulesEvaluator()
	pol, err := policy.NewEnforcer(policyRepo, eval)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	return repo, reg, prov, pol
}

func TestNewKeyOrchestrator_allDependencies_succeeds(t *testing.T) {
	repo, reg, prov, pol := allDeps(t)
	orch, err := NewKeyOrchestrator(repo, reg, prov, pol)
	if err != nil {
		t.Fatalf("NewKeyOrchestrator: %v", err)
	}
	if orch == nil {
		t.Fatal("NewKeyOrchestrator returned nil")
	}
}

func TestNewKeyOrchestrator_nilRepository_returnsError(t *testing.T) {
	_, reg, prov, pol := allDeps(t)
	_, err := NewKeyOrchestrator(nil, reg, prov, pol)
	if err == nil {
		t.Fatal("expected error for nil repository")
	}
}

func TestNewKeyOrchestrator_nilTemplateRegistry_returnsError(t *testing.T) {
	repo, _, prov, pol := allDeps(t)
	_, err := NewKeyOrchestrator(repo, nil, prov, pol)
	if err == nil {
		t.Fatal("expected error for nil template registry")
	}
}

func TestNewKeyOrchestrator_nilProviderRegistry_returnsError(t *testing.T) {
	repo, reg, _, pol := allDeps(t)
	_, err := NewKeyOrchestrator(repo, reg, nil, pol)
	if err == nil {
		t.Fatal("expected error for nil provider registry")
	}
}

func TestNewKeyOrchestrator_nilPolicyEngine_returnsError(t *testing.T) {
	repo, reg, prov, _ := allDeps(t)
	_, err := NewKeyOrchestrator(repo, reg, prov, nil)
	if err == nil {
		t.Fatal("expected error for nil policy engine")
	}
}

func TestNewKeyOrchestrator_returnsInterface(t *testing.T) {
	repo, reg, prov, pol := allDeps(t)
	var orch KeyOrchestrator
	orch, err := NewKeyOrchestrator(repo, reg, prov, pol)
	if err != nil {
		t.Fatalf("NewKeyOrchestrator: %v", err)
	}
	_ = orch // confirms the return type satisfies the interface
}

func TestKeyOrchestrator_TransformKey(t *testing.T) {
	tc := []struct {
		name          string
		wantErr       bool
		errCode       errors.Code
		transformSpec TransformKeySpec
		policyRules   *policy.Rules
	}{
		// {
		// 	name:          "empty req fails",
		// 	wantErr:       true,
		// 	errCode:       errors.CodeInvalidArgument,
		// 	transformSpec: TransformKeySpec{},
		// },
		{
			name:    "key name only",
			wantErr: false,
			transformSpec: TransformKeySpec{
				KeyName: "test-key-1",
			},
		},
		{
			name:    "with scope specification",
			wantErr: true,
			errCode: errors.CodeNotImplemented,
			transformSpec: TransformKeySpec{
				KeyName:            "test-key-2",
				ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignaturePrehashed),
			},
		},
		{
			name:    "with template ID",
			wantErr: false,
			transformSpec: TransformKeySpec{
				KeyName:    "test-key-3",
				TemplateID: "ml-dsa-65",
			},
		},
		{
			name:    "with retain bytes",
			wantErr: true,
			errCode: errors.CodeNotImplemented,
			transformSpec: TransformKeySpec{
				KeyName:     "test-key-4",
				RetainBytes: true,
			},
		},
		{
			name:    "failed when template ID is not allowed by policy",
			wantErr: true,
			errCode: errors.CodePolicyViolation,
			transformSpec: TransformKeySpec{
				KeyName:    "test-key-5",
				TemplateID: "ml-dsa-65", // not allowed by policy
			},
			policyRules: &policy.Rules{
				Version:          "1",
				AllowedTemplates: []string{"ecdsa-p256-sha256-der"},
				AllowedOperations: &policy.OperationRule{
					KeyOperations: []string{string(core.OperationCreateKey)},
				},
			},
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			orch, keys, providers, engine, templates := setupOrchestratorFull(t)
			// Seed policy
			policyName := fmt.Sprintf("pol-%s", tt.name)
			initTemplateID := "ecdsa-p256-sha256-der"
			initVersion := uint32(1)
			keyName := tt.transformSpec.KeyName
			keyID := keyName

			seedPolicy(t, ctx, engine, policyName, tt.policyRules)
			k0, v0 := setupFirstKeyVersion(t, ctx, keyName, keyID, providers, templates, keys, policyName, initTemplateID, initVersion)
			// transform the key
			metadata, err := orch.TransformKey(ctx, tt.transformSpec)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errCode == errors.CodeNotImplemented {
					require.True(t, errors.IsNotImplemented(err))
				}
				return
			}
			require.NoError(t, err)

			k1, err := keys.GetKeyByName(ctx, keyName)
			require.NoError(t, err)
			v1, err := keys.GetCurrentVersion(ctx, keyID)
			require.NoError(t, err)
			v11, err := keys.GetVersion(ctx, keyID, metadata.Version)
			require.NoError(t, err)
			// GetCurrent and GetVersion should return the same version
			require.Equal(t, v1, v11)
			assertKeyStaticFieldsUnchanged(t, k0, k1)
			// Version match
			require.Equal(t, initVersion+1, k1.CurrentVersion)
			require.Equal(t, initVersion+1, metadata.Version)
			require.Equal(t, initVersion+1, v1.Version)
			// Template match spec
			if tt.transformSpec.TemplateID != "" {
				require.Equal(t, tt.transformSpec.TemplateID, v1.TemplateId)
			}
			if tt.transformSpec.ScopeSpecification != nil {
				// scope specification is updated
				// TODO: this may be updated depending on the scope specification lifecycle rules
				require.Equal(t, tt.transformSpec.ScopeSpecification, k1.ScopeSpecification)
			}
			if tt.transformSpec.RetainBytes {
				// bytes are retained
				require.Equal(t, v0.KeyMaterial, v1.KeyMaterial)
			}
			assertMetadataMatchKeyAndVersion(t, ctx, metadata, k1, v1)
		})
	}
}

func seedPolicy(t *testing.T, ctx context.Context, engine policy.Engine, name string, rules *policy.Rules) {
	if rules != nil {
		_ = seedScopePolicy(t, ctx, engine, name, rules)
	} else {
		defaultRules := &policy.Rules{
			Version:          "1",
			AllowedTemplates: []string{"ecdsa-p256-sha256-der", "ml-dsa-65"},
			AllowedOperations: &policy.OperationRule{
				KeyOperations: []string{string(core.OperationCreateKey)},
			},
		}
		_ = seedScopePolicy(t, ctx, engine, name, defaultRules)
	}
}
func assertMetadataMatchKeyAndVersion(t *testing.T, ctx context.Context, metadata *KeyMetadata, k *key.Key, v *key.Version) {
	specBytes, err := metadata.ScopeSpec.Serialize(ctx)
	require.NoError(t, err)
	require.Equal(t, k.ScopeSpecification, specBytes)
	require.Equal(t, k.PolicyId, metadata.Policy)
	require.Equal(t, k.Name, metadata.Name)
	require.Equal(t, k.Primitive, metadata.Primitive)

	// TODO: Lifecycle state in metadata is lifecycle state of key or version?
	// require.Equal(t, v1.State, metadata.LifecycleState)
	require.Equal(t, v.ProviderId, metadata.Provider)
}

func setupFirstKeyVersion(t *testing.T, ctx context.Context, keyName string, keyID string, providers provider.Registry, templates template.Registry, keys key.Repository,
	policyName string, initTemplateID string, initVersion uint32) (*key.Key, *key.Version) {
	provider0, err := providers.MatchForTemplate(ctx, initTemplateID)
	require.NoError(t, err)
	templateInfo0, err := templates.Get(ctx, initTemplateID)
	require.NoError(t, err)
	provResp, err := provider0.GenerateKey(ctx, &providerpb.GenerateKeyRequest{
		Algorithm: templateInfo0.GetAlgorithm(),
	})
	require.NoError(t, err)
	keyMaterial := provResp.GetKeyMaterial()

	// Create a key to transform
	versionID := fmt.Sprintf("%s:%d", keyName, initVersion)
	scopeSpec := scopeSpecWithScope(t, core.ScopeSignatureStandard)
	k0, err := key.NewKey(ctx, keyID, policyName, scopeSpec, initVersion, key.WithName(keyName))
	require.NoError(t, err)
	v0, err := key.NewVersion(ctx, versionID, keyID, initTemplateID, provider0.Name(), initVersion, keyMaterial, key.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	require.NoError(t, err)
	err = keys.CreateKey(ctx, k0, v0)
	require.NoError(t, err)
	return k0, v0
}

func assertKeyStaticFieldsUnchanged(t *testing.T, k0, k1 *key.Key) {
	require.Equal(t, k0.Name, k1.Name)
	require.Equal(t, k0.PolicyId, k1.PolicyId)
	require.Equal(t, k0.Primitive, k1.Primitive)
	require.Equal(t, k0.PublicId, k1.PublicId)
	require.Equal(t, k0.Labels, k1.Labels)
}
