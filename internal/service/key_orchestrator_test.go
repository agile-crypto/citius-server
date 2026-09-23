package service_test

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/agile-crypto/citius-core/service"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	core "github.com/agile-crypto/citius-core"
	"github.com/agile-crypto/citius-core/errors"
	corekey "github.com/agile-crypto/citius-core/key"
	corepolicy "github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	coretemplate "github.com/agile-crypto/citius-core/template"
	providerpb "github.com/agile-crypto/citius-provider-go/gen/provider"
	"github.com/agile-crypto/vault-storage/key"
	"github.com/agile-crypto/vault-storage/policy"
	"github.com/agile-crypto/vault-storage/template"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// service.NewKeyOrchestrator Constructor Tests
// ============================================================================

// allDeps creates a full set of valid dependencies for the constructor.
func allDeps(t *testing.T) (corekey.Repository, coretemplate.Registry, provider.Registry, corepolicy.Engine) {
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
	eval := corepolicy.NewSimpleRulesEvaluator()
	pol, err := corepolicy.NewEnforcer(policyRepo, eval)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	return repo, reg, prov, pol
}

func TestNewKeyOrchestrator_allDependencies_succeeds(t *testing.T) {
	repo, reg, prov, pol := allDeps(t)
	orch, err := service.NewKeyOrchestrator(repo, reg, prov, pol)
	if err != nil {
		t.Fatalf("service.NewKeyOrchestrator: %v", err)
	}
	if orch == nil {
		t.Fatal("service.NewKeyOrchestrator returned nil")
	}
}

func TestNewKeyOrchestrator_nilRepository_returnsError(t *testing.T) {
	_, reg, prov, pol := allDeps(t)
	_, err := service.NewKeyOrchestrator(nil, reg, prov, pol)
	if err == nil {
		t.Fatal("expected error for nil repository")
	}
}

func TestNewKeyOrchestrator_nilTemplateRegistry_returnsError(t *testing.T) {
	repo, _, prov, pol := allDeps(t)
	_, err := service.NewKeyOrchestrator(repo, nil, prov, pol)
	if err == nil {
		t.Fatal("expected error for nil template registry")
	}
}

func TestNewKeyOrchestrator_nilProviderRegistry_returnsError(t *testing.T) {
	repo, reg, _, pol := allDeps(t)
	_, err := service.NewKeyOrchestrator(repo, reg, nil, pol)
	if err == nil {
		t.Fatal("expected error for nil provider registry")
	}
}

func TestNewKeyOrchestrator_nilPolicyEngine_returnsError(t *testing.T) {
	repo, reg, prov, _ := allDeps(t)
	_, err := service.NewKeyOrchestrator(repo, reg, prov, nil)
	if err == nil {
		t.Fatal("expected error for nil policy engine")
	}
}

func TestNewKeyOrchestrator_returnsInterface(t *testing.T) {
	repo, reg, prov, pol := allDeps(t)
	var orch service.KeyOrchestrator
	orch, err := service.NewKeyOrchestrator(repo, reg, prov, pol)
	if err != nil {
		t.Fatalf("service.NewKeyOrchestrator: %v", err)
	}
	_ = orch // confirms the return type satisfies the interface
}

func TestKeyOrchestrator_TransformKey(t *testing.T) {
	tc := []struct {
		name             string
		initialScopeSpec *core.ScopeSpecification
		wantErr          bool
		errCode          errors.Code
		transformSpec    service.TransformKeySpec
		policyRules      *corepolicy.Rules
	}{
		{
			name:    "missing key name",
			wantErr: true,
			errCode: errors.CodeInvalidArgument,
			transformSpec: service.TransformKeySpec{
				TemplateID: "ml-dsa-65",
			},
		},
		{
			name:    "key name only",
			wantErr: true,
			errCode: errors.CodeInvalidArgument,
			transformSpec: service.TransformKeySpec{
				KeyName: "test-key-1",
			},
		},
		{
			name:             "with unchanged scope specification",
			initialScopeSpec: scopeSpecWithScope(t, core.ScopeSignatureStandard),
			wantErr:          false,
			transformSpec: service.TransformKeySpec{
				KeyName:            "test-key-2",
				ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignatureStandard),
			},
		},
		{
			name:             "with changed scope specification",
			initialScopeSpec: scopeSpecWithScope(t, core.ScopeSignatureStandard),
			wantErr:          false,
			transformSpec: service.TransformKeySpec{
				KeyName: "test-key-2-changed",
				ScopeSpecification: &core.ScopeSpecification{
					Scope: core.ScopeSignatureStandard,
					SecurityProps: &core.SecurityProperties{
						QuantumSafe: true,
					},
				},
			},
		},
		{
			name:    "with template ID",
			wantErr: false,
			transformSpec: service.TransformKeySpec{
				KeyName:            "test-key-3",
				TemplateID:         "ml-dsa-65",
				ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignatureStandard),
			},
		},
		{
			name:    "with retain bytes",
			wantErr: true,
			errCode: errors.CodeNotImplemented,
			transformSpec: service.TransformKeySpec{
				KeyName:            "test-key-4",
				ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignatureStandard),
				RetainBytes:        true,
			},
		},
		{
			name:    "failed when template ID is not allowed by policy",
			wantErr: true,
			errCode: errors.CodePolicyViolation,
			transformSpec: service.TransformKeySpec{
				KeyName:            "test-key-5",
				TemplateID:         "ml-dsa-65", // not allowed by policy
				ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignatureStandard),
			},
			policyRules: &corepolicy.Rules{
				Version:          "1",
				AllowedTemplates: []string{"ecdsa-p256-sha256-der"},
				AllowedOperations: &corepolicy.OperationRule{
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
			// for tests with missing key name, we generate a unique key name to avoid collisions used for creating the initial key version
			if keyName == "" {
				keyName = fmt.Sprintf("key-%s", tt.name)
			}
			keyID := keyName

			seedPolicy(t, ctx, engine, policyName, tt.policyRules)
			if tt.initialScopeSpec == nil {
				tt.initialScopeSpec = scopeSpecWithScope(t, core.ScopeSignatureStandard)
			}
			k0, v0 := setupFirstKeyVersion(t, ctx, keyName, keyID, providers, templates, keys, policyName, initTemplateID, initVersion, tt.initialScopeSpec)
			// reset keyName in case it was generated for the test
			keyName = tt.transformSpec.KeyName
			// transform the key
			metadata, err := orch.TransformKey(ctx, tt.transformSpec)
			if tt.wantErr {
				require.Error(t, err)
				var coreErr *errors.Error
				require.True(t, errors.As(err, &coreErr))
				require.Equal(t, tt.errCode, coreErr.Code)
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
			// Immutable fields of the key should not change after transformation
			assertKeyStaticFieldsUnchanged(t, k0, k1)
			// Version match
			assertVersionConsistent(t, initVersion+1, k1, v1, metadata)
			// Template match spec
			assertMatchTransformSpec(t, tt.transformSpec, v1, k1, v0)
			assertMetadataMatchKeyAndVersion(t, ctx, metadata, k1, v1)
		})
	}
}

func assertMatchTransformSpec(t *testing.T, expectedSpec service.TransformKeySpec, v *corekey.Version, k *corekey.Key, oldVersion *corekey.Version) {
	if expectedSpec.TemplateID != "" {
		require.Equal(t, expectedSpec.TemplateID, v.TemplateId)
	}
	if expectedSpec.ScopeSpecification != nil {
		actual := &core.ScopeSpecification{}
		require.NoError(t, actual.Deserialize(context.Background(), v.GetScopeSpecification()))
		require.Equal(t, expectedSpec.ScopeSpecification, actual)
		require.NotEmpty(t, oldVersion.GetScopeSpecification())
	}
	if expectedSpec.RetainBytes {
		// bytes are retained
		require.Equal(t, oldVersion.KeyMaterial, v.KeyMaterial)
	}
}
func assertVersionConsistent(t *testing.T, expectedVersion uint32, k *corekey.Key, v *corekey.Version, md *service.KeyMetadata) {
	require.Equal(t, expectedVersion, k.CurrentVersion)
	require.Equal(t, expectedVersion, md.Version)
	require.Equal(t, expectedVersion, v.Version)
}

func TestKeyOrchestrator_TransformKey_SuccessiveTransforms(t *testing.T) {
	tc := []struct {
		name   string
		rounds int
	}{
		{
			name:   "2 rounds",
			rounds: 2,
		},
		{
			name:   "3 rounds",
			rounds: 3,
		},
		{
			name:   "N rounds",
			rounds: rand.Intn(10) + 4, // random number of rounds between 4 and 13
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
			keyName := fmt.Sprintf("key-%s", tt.name)
			keyID := keyName

			seedPolicy(t, ctx, engine, policyName, nil)
			k0, _ := setupFirstKeyVersion(t, ctx, keyName, keyID, providers, templates, keys, policyName, initTemplateID, initVersion, scopeSpecWithScope(t, core.ScopeSignatureStandard))
			for i := range tt.rounds {
				// transform the key
				metadata, err := orch.TransformKey(ctx, service.TransformKeySpec{
					KeyName:            keyName,
					ScopeSpecification: scopeSpecWithScope(t, core.ScopeSignatureStandard),
				})
				require.NoError(t, err)
				k1, err := keys.GetKeyByName(ctx, keyName)
				require.NoError(t, err)
				v1, err := keys.GetCurrentVersion(ctx, keyID)
				require.NoError(t, err)
				v11, err := keys.GetVersion(ctx, keyID, metadata.Version)
				require.NoError(t, err)
				// GetCurrent and GetVersion should return the same version
				require.Equal(t, v1, v11)
				// Immutable fields of the key should not change after transformation
				assertKeyStaticFieldsUnchanged(t, k0, k1)
				// Version match
				assertVersionConsistent(t, initVersion+uint32(i)+1, k1, v1, metadata)
				assertMetadataMatchKeyAndVersion(t, ctx, metadata, k1, v1)
			}
		})
	}
}

func seedPolicy(t *testing.T, ctx context.Context, engine corepolicy.Engine, name string, rules *corepolicy.Rules) {
	if rules != nil {
		_ = seedScopePolicy(t, ctx, engine, name, rules)
	} else {
		defaultRules := &corepolicy.Rules{
			Version:          "1",
			AllowedTemplates: []string{"ecdsa-p256-sha256-der", "ml-dsa-65"},
			AllowedOperations: &corepolicy.OperationRule{
				KeyOperations: []string{string(core.OperationCreateKey)},
			},
		}
		_ = seedScopePolicy(t, ctx, engine, name, defaultRules)
	}
}
func assertMetadataMatchKeyAndVersion(t *testing.T, ctx context.Context, metadata *service.KeyMetadata, k *corekey.Key, v *corekey.Version) {
	specBytes, err := metadata.ScopeSpec.Serialize(ctx)
	require.NoError(t, err)
	require.Equal(t, v.GetScopeSpecification(), specBytes)
	require.Equal(t, k.PolicyId, metadata.Policy)
	require.Equal(t, k.Name, metadata.Name)
	require.Equal(t, k.Primitive, metadata.Primitive)

	// TODO: Lifecycle state in metadata is lifecycle state of key or version?
	// require.Equal(t, v1.State, metadata.LifecycleState)
	require.Equal(t, v.ProviderId, metadata.Provider)
}

func setupFirstKeyVersion(t *testing.T, ctx context.Context, keyName string, keyID string, providers provider.Registry, templates coretemplate.Registry, keys corekey.Repository,
	policyName string, initTemplateID string, initVersion uint32, scopeSpec *core.ScopeSpecification) (*corekey.Key, *corekey.Version) {
	provider0, err := providers.Match(ctx, provider.Requirements{TemplateID: initTemplateID})
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
	k0, err := corekey.NewKey(ctx, keyID, policyName, scopeSpec.Scope.GetPrimitive(), initVersion, corekey.WithName(keyName))
	require.NoError(t, err)
	v0, err := corekey.NewVersion(ctx, versionID, keyID, initTemplateID, provider0.Name(), initVersion, keyMaterial, scopeSpec, corekey.WithState(types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE))
	require.NoError(t, err)
	err = keys.CreateKey(ctx, k0, v0)
	require.NoError(t, err)
	return k0, v0
}

// Check that the static fields of both keys are equal. Static fields are those that should not change
// after initial creation of the key: Name, PolicyId, Primitive, PublicId, and Labels.
func assertKeyStaticFieldsUnchanged(t *testing.T, k0, k1 *corekey.Key) {
	require.Equal(t, k0.Name, k1.Name)
	require.Equal(t, k0.PolicyId, k1.PolicyId)
	require.Equal(t, k0.Primitive, k1.Primitive)
	require.Equal(t, k0.PublicId, k1.PublicId)
	require.Equal(t, k0.Labels, k1.Labels)
}
