package key

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
)

// helper: create a valid Key domain object.
func newTestKey(publicID, name string, scopeSpec *core.ScopeSpec) (*Key, error) {
	return newKey(context.Background(), publicID, "policy-test", scopeSpec, 1, WithName(name))
}

func mustNewCreateKeyInputs(
	t *testing.T,
	ctx context.Context,
	publicID, name, templateID, providerID, policyID string,
	scopeSpec *core.ScopeSpec,
	initialVersion uint32,
	keyMaterial []byte,
	status storepb.KeyStatus,
) (*Key, *Version) {
	t.Helper()
	k, err := newKey(ctx, publicID, policyID, scopeSpec, initialVersion, WithName(name), WithStatus(status))
	if err != nil {
		t.Fatalf("newKey(%s): %v", publicID, err)
	}
	v, err := newVersion(
		ctx,
		defaultKeyVersionID(publicID, initialVersion),
		publicID,
		templateID,
		providerID,
		initialVersion,
		keyMaterial,
		WithStatus(status),
	)
	if err != nil {
		t.Fatalf("newVersion(%s,%d): %v", publicID, initialVersion, err)
	}
	return k, v
}

// helper: create a key+version in the store (for tests that need setup).
func mustCreateKey(t *testing.T, r Repository, publicID, name string, scope string) {
	t.Helper()
	ctx := context.Background()
	scopeSpec := &core.ScopeSpec{
		Primitive: core.Primitive(scope),
		Scope:     core.SignatureScopeStandard,
	}
	k, v := mustNewCreateKeyInputs(t, ctx, publicID, name, "template-id", "software", "policy-test", scopeSpec, 1, []byte("fake-key-bytes"), storepb.KeyStatus_KEY_STATUS_ACTIVE)
	if err := r.CreateKey(ctx, k, v, WithInitialVersion(1)); err != nil {
		t.Fatalf("mustCreateKey(%s): %v", publicID, err)
	}
}

var repoFn = func() Repository {
	storage := &logical.InmemStorage{}
	r, err := NewVaultRepository(context.Background(), storage)
	if err != nil {
		panic("failed to create VaultRepository: " + err.Error())
	}
	return r
}

// ============================================================================
// CreateKey / GetKey
// ============================================================================

func Test_VaultRepository_CreateKey_GetKey_roundtrip(t *testing.T) {
	r := repoFn()
	ctx := context.Background()

	scopeSpec := &core.ScopeSpec{
		Primitive: core.PrimitiveSignature,
		Scope:     core.SignatureScopeStandard,
	}
	initialVersionNbr := uint32(1)
	k, v := mustNewCreateKeyInputs(t, ctx, "key_01HXYZ", "signing-key", "template-id", "software", "policy-test", scopeSpec, initialVersionNbr, []byte("fake-key-bytes"), storepb.KeyStatus_KEY_STATUS_ACTIVE)
	if err := r.CreateKey(ctx, k, v, WithInitialVersion(initialVersionNbr)); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := r.GetKeyById(ctx, "key_01HXYZ")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.PublicId != "key_01HXYZ" {
		t.Errorf("PublicID: got %q want %q", got.PublicId, "key_01HXYZ")
	}
	if got.Name != "signing-key" {
		t.Errorf("Name: got %q want %q", got.Name, "signing-key")
	}
	if got.CurrentVersion != initialVersionNbr {
		t.Errorf("CurrentVersion: got %d want %d", got.CurrentVersion, initialVersionNbr)
	}
}

func Test_VaultRepository_CreateKey_setsVersion1(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	scopeSpec := &core.ScopeSpec{
		Primitive: core.PrimitiveSignature,
		Scope:     core.SignatureScopeStandard,
	}
	k, v := mustNewCreateKeyInputs(t, ctx, "key_01HXYZ", "signing-key", "template-id", "software", "policy-test", scopeSpec, 1, []byte("fake-key-bytes"), storepb.KeyStatus_KEY_STATUS_ACTIVE)
	if err := r.CreateKey(ctx, k, v, WithInitialVersion(1)); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := r.GetVersion(ctx, "key_01HXYZ", 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if got.Version != 1 {
		t.Errorf("VersionNumber: got %d want 1", got.Version)
	}
}

func Test_VaultRepository_CreateKey_setsStatus(t *testing.T) {
	testCases := []struct {
		name       string
		keyID      string
		wantStatus storepb.KeyStatus
	}{
		{"default_status", "kc01", storepb.KeyStatus_KEY_STATUS_ACTIVE},
		{"explicit_active", "kc02", storepb.KeyStatus_KEY_STATUS_ACTIVE},
		{"explicit_compromised", "kc03", storepb.KeyStatus_KEY_STATUS_COMPROMISED},
	}
	r := repoFn()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			km := []byte("fake-key-bytes")
			k, v := mustNewCreateKeyInputs(t, ctx, tc.keyID, tc.keyID, "template-id", "software", "policy-test", &core.ScopeSpec{
				Primitive: core.PrimitiveSignature,
				Scope:     core.SignatureScopeStandard,
			}, 0, km, tc.wantStatus)
			err := r.CreateKey(ctx, k, v, WithInitialVersion(0))
			require.NoErrorf(err, "CreateKey error for key %s: %v", tc.keyID, err)
			v0, err := r.GetCurrentVersion(ctx, tc.keyID)
			require.NoErrorf(err, "GetCurrentVersion error for key %s: %v", tc.keyID, err)
			assert.Equal(uint32(0), v0.Version, "initial version should be 0")
			assert.Equal(tc.wantStatus, v0.GetStatus(), "version should have expected status")
		})
	}

}
func Test_VaultRepository_GetKey_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetKeyById(context.Background(), "key_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

func Test_VaultRepository_CreateKey_duplicate_returnsError(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	scopeSpec := &core.ScopeSpec{
		Primitive: core.PrimitiveSignature,
		Scope:     core.SignatureScopeStandard,
	}
	k1, v1 := mustNewCreateKeyInputs(t, ctx, "key_01HXYZ", "signing-key", "template-id", "software", "policy-test", scopeSpec, 1, []byte("fake-key-bytes"), storepb.KeyStatus_KEY_STATUS_ACTIVE)
	_ = r.CreateKey(ctx, k1, v1, WithInitialVersion(1))
	k2, v2 := mustNewCreateKeyInputs(t, ctx, "key_01HXYZ", "signing-key2", "template-id2", "software", "policy-test2", scopeSpec, 1, []byte("fake-key-bytes2"), storepb.KeyStatus_KEY_STATUS_ACTIVE)
	err := r.CreateKey(ctx, k2, v2, WithInitialVersion(1))
	if err == nil {
		t.Fatal("expected error for duplicate key")
	}
	if !errors.IsAlreadyExists(err) {
		t.Errorf("expected AlreadyExists, got: %v", err)
	}
}

func Test_VaultRepository_GetKey_returnsClone(t *testing.T) {
	// Mutating the returned key should NOT affect the stored copy.
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01HXYZ", "original", "signature")

	got, _ := r.GetKeyById(ctx, "key_01HXYZ")
	got.Name = "mutated"

	got2, _ := r.GetKeyById(ctx, "key_01HXYZ")
	if got2.Name != "original" {
		t.Errorf("stored key was mutated: got %q want %q", got2.Name, "original")
	}
}

// ============================================================================
// DeleteKey (cascading)
// ============================================================================

func Test_VaultRepository_DeleteKey_success(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01HXYZ", "k", "signature")

	if err := r.DeleteKey(ctx, "key_01HXYZ"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	_, err := r.GetKeyById(ctx, "key_01HXYZ")
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound after delete, got: %v", err)
	}
}

func Test_VaultRepository_DeleteKey_cascadesVersions(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	r := repoFn()
	ctx := context.Background()
	kid := "key_01HXYZ"
	mustCreateKey(t, r, kid, "k", "signature")
	v, err := r.GetCurrentVersion(ctx, kid)
	if err != nil {
		t.Errorf("unexpected error while getting current version of key %s", kid)
	}
	v2 := v.Clone()
	v2.Version = v.Version + 1
	v2.PublicId = "ver_02"
	vNext, err := newVersion(ctx, defaultKeyVersionID(kid, 2), kid, "template", "software", 2, []byte("key_version_1"), WithStatus(storepb.KeyStatus_KEY_STATUS_ACTIVE))
	require.NoError(err, "error creating key version 2")
	err = r.AddVersion(ctx, vNext)
	if err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	vNext2, err := newVersion(ctx, defaultKeyVersionID(kid, 3), kid, "template", "software", 3, []byte("key_version_2"), WithStatus(storepb.KeyStatus_KEY_STATUS_ACTIVE))
	require.NoError(err, "error creating key version 3")
	err = r.AddVersion(ctx, vNext2)
	require.NoError(err, "got error when adding second version")
	k, err := r.GetKeyById(ctx, kid)
	require.NoErrorf(err, "error when getting key with id=%s", kid)
	assert.Equal(uint32(v2.Version+1), k.CurrentVersion, "current version should be 2")
	err = r.DeleteKey(ctx, "key_01HXYZ")
	require.NoError(err, "DeleteKey should not return error")
	_, err = r.GetKeyById(ctx, "key_01HXYZ")
	require.True(errors.IsKeyNotFound(err), "expected KeyNotFound after delete, got: %v", err)
	// Both versions should be gone.
	_, err = r.GetVersion(ctx, "key_01HXYZ", 1)
	require.True(errors.IsKeyNotFound(err), "expected VersionNotFound for version 1 after cascading delete")
	_, err = r.GetVersion(ctx, "key_01HXYZ", 2)
	require.True(errors.IsKeyNotFound(err), "expected VersionNotFound for version 2 after cascading delete")
}

func Test_VaultRepository_DeleteKey_notFound_returnsError(t *testing.T) {
	r := repoFn()
	err := r.DeleteKey(context.Background(), "key_doesnotexist")
	if err == nil {
		t.Fatal("expected error for deleting non-existent key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

// ============================================================================
// ListKeys
// ============================================================================

func Test_VaultRepository_ListKeys_all(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k1", "signature")
	mustCreateKey(t, r, "key_02", "k2", "ml-dsa-65")

	keys, err := r.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("ListKeys: got %d want 2", len(keys))
	}
	// Verify full Key objects are returned, not just names.
	for _, k := range keys {
		if k.PublicId == "" {
			t.Error("ListKeys returned key with empty PublicID")
		}
	}
}

func Test_VaultRepository_ListKeys_multipleKeys(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k1", "signature")
	mustCreateKey(t, r, "key_02", "k2", "ml-dsa-65")
	mustCreateKey(t, r, "key_03", "k3", "signature")

	keys, err := r.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("ListKeys: got %d want 3", len(keys))
	}
}

func Test_VaultRepository_ListKeys_empty(t *testing.T) {
	r := repoFn()
	keys, err := r.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if keys == nil {
		t.Error("ListKeys should return empty slice, not nil")
	}
}

// ============================================================================
// UpdateKey
// ============================================================================

func Test_VaultRepository_UpdateKey_success(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01HXYZ", "signing-key", "signature")

	// Build an updated Key with new status.
	updated := NewKey(&storepb.Key{
		PublicId:       "key_01HXYZ",
		Name:           "signing-key",
		Primitive:      "signature",
		Status:         storepb.KeyStatus_KEY_STATUS_SUSPENDED,
		CurrentVersion: 1,
	})
	if err := r.UpdateKey(ctx, updated); err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}

	got, err := r.GetKeyById(ctx, "key_01HXYZ")
	if err != nil {
		t.Fatalf("GetKey after update: %v", err)
	}
	if got.GetStatus() != storepb.KeyStatus_KEY_STATUS_SUSPENDED {
		t.Errorf("status: got %v want SUSPENDED", got.GetStatus())
	}
}

func Test_VaultRepository_UpdateKey_notFound_returnsError(t *testing.T) {
	r := repoFn()
	k, err := newTestKey("id", "signing-key", &core.ScopeSpec{
		Primitive: core.PrimitiveSignature,
		Scope:     core.SignatureScopeStandard,
	})
	require.NoError(t, err, "error when creating key")
	err = r.UpdateKey(context.Background(), k)
	require.NotNil(t, err)
	require.Truef(t, errors.IsKeyNotFound(err), "expected KeyNotFound, got: %v", err)
}

func Test_VaultRepository_UpdateKey_nil_returnsError(t *testing.T) {
	r := repoFn()
	err := r.UpdateKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

// ============================================================================
// AddVersion / GetVersion
// ============================================================================

func Test_VaultRepository_AddVersion_GetVersion_roundtrip(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k", "signature")

	v, err := newVersion(ctx, defaultKeyVersionID("key_01", 2), "key_01", "template", "software", 2, []byte("key_version_2"), WithStatus(storepb.KeyStatus_KEY_STATUS_ACTIVE))
	require.NoError(t, err, "error creating key version input")
	err = r.AddVersion(ctx, v)
	require.NoErrorf(t, err, "error when adding version (%s,%d)", "key_01", 2)

	got, err := r.GetVersion(ctx, "key_01", 2)
	require.NoErrorf(t, err, "error when getting version (%s,%d)", "key_01", 2)
	assert.Equal(t, "key_01", got.KeyId)
	assert.Equal(t, uint32(2), got.Version)
}

func Test_VaultRepository_AddVersion_GetOldVersion(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k", "signature")

	v, err := newVersion(ctx, defaultKeyVersionID("key_01", 2), "key_01", "template", "software", 2, []byte("key_version_2"), WithStatus(storepb.KeyStatus_KEY_STATUS_ACTIVE))
	require.NoError(t, err, "error creating key version input")
	err = r.AddVersion(ctx, v)
	if err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	got, err := r.GetVersion(ctx, "key_01", 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if got.Version != 1 {
		t.Errorf("VersionNumber: got %d want 1", got.Version)
	}
	if got.Version != 1 {
		t.Errorf("VersionNumber: got %d want 1", got.Version)
	}
}

func Test_VaultRepository_GetVersion_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetVersion(context.Background(), "key_01", 99)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound error, got: %v", err)
	}
}

func Test_VaultRepository_AddVersion_returnsClone(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k", "signature")

	// Fetch version 1 (created by CreateKey) and mutate the returned clone.
	got, _ := r.GetVersion(ctx, "key_01", 1)
	got.ProviderId = "mutated"

	// Re-fetch — should still have original value.
	got2, _ := r.GetVersion(ctx, "key_01", 1)
	if got2.ProviderId != "software" {
		t.Error("GetVersion should return a clone — stored value was mutated")
	}
}

func Test_VaultRepository_AddVersion_keyNotFound_returnsError(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	v, err := newVersion(ctx, defaultKeyVersionID("key_missing", 1), "key_missing", "template", "software", 1, []byte("key_material"), WithStatus(storepb.KeyStatus_KEY_STATUS_ACTIVE))
	require.NoError(t, err, "error creating key version input")
	err = r.AddVersion(ctx, v)
	if err == nil {
		t.Fatal("expected error for adding version to non-existent key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

// ============================================================================
// GetKeyByName
// ============================================================================

func Test_VaultRepository_GetKeyByName_existing(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "my-key", "signature")

	got, err := r.GetKeyByName(ctx, "my-key")
	require.NoError(t, err)
	assert.Equal(t, "key_01", got.PublicId)
	assert.Equal(t, "my-key", got.Name)
}

func Test_VaultRepository_GetKeyByName_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetKeyByName(context.Background(), "does-not-exist")
	require.Error(t, err)
	require.True(t, errors.IsKeyNotFound(err), "expected KeyNotFound, got: %v", err)
}

func Test_VaultRepository_GetKeyByName_multipleKeys_returnsCorrectOne(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "alpha", "signature")
	mustCreateKey(t, r, "key_02", "beta", "signature")

	got, err := r.GetKeyByName(ctx, "beta")
	require.NoError(t, err)
	assert.Equal(t, "key_02", got.PublicId)
}

// ============================================================================
// Name-to-ID mapping: storage and caching through key lifecycle
// ============================================================================

func Test_VaultRepository_GetKeyByName_afterUpdate_stillResolvable(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "signing-key", "signature")

	updated := NewKey(&storepb.Key{
		PublicId:       "key_01",
		Name:           "signing-key",
		Primitive:      "signature",
		Status:         storepb.KeyStatus_KEY_STATUS_SUSPENDED,
		CurrentVersion: 1,
	})
	require.NoError(t, r.UpdateKey(ctx, updated))

	got, err := r.GetKeyByName(ctx, "signing-key")
	require.NoError(t, err)
	assert.Equal(t, "key_01", got.PublicId)
	assert.Equal(t, storepb.KeyStatus_KEY_STATUS_SUSPENDED, got.GetStatus())
}

func Test_VaultRepository_GetKeyByName_afterDeletion_notFound(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "signing-key", "signature")

	require.NoError(t, r.DeleteKey(ctx, "key_01"))

	_, err := r.GetKeyByName(ctx, "signing-key")
	require.Error(t, err)
	require.True(t, errors.IsKeyNotFound(err), "expected KeyNotFound after deletion, got: %v", err)
}

func Test_VaultRepository_CreateKey_duplicateName_notAllowed(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "signing-key", "signature")

	scopeSpec := &core.ScopeSpec{Primitive: core.PrimitiveSignature, Scope: core.SignatureScopeStandard}
	k2, v2 := mustNewCreateKeyInputs(t, ctx, "key_02", "signing-key", "template-id", "software", "policy-test", scopeSpec, 1, []byte("other-key-bytes"), storepb.KeyStatus_KEY_STATUS_ACTIVE)
	err := r.CreateKey(ctx, k2, v2, WithInitialVersion(1))
	require.Error(t, err)
	require.True(t, errors.IsAlreadyExists(err), "expected AlreadyExists for duplicate name, got: %v", err)
}

func Test_VaultRepository_CreateKey_sameNameAllowedAfterDeletion(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "signing-key", "signature")
	require.NoError(t, r.DeleteKey(ctx, "key_01"))

	scopeSpec := &core.ScopeSpec{Primitive: core.PrimitiveSignature, Scope: core.SignatureScopeStandard}
	k2, v2 := mustNewCreateKeyInputs(t, ctx, "key_02", "signing-key", "template-id", "software", "policy-test", scopeSpec, 1, []byte("new-key-bytes"), storepb.KeyStatus_KEY_STATUS_ACTIVE)
	require.NoError(t, r.CreateKey(ctx, k2, v2, WithInitialVersion(1)))

	got, err := r.GetKeyByName(ctx, "signing-key")
	require.NoError(t, err)
	assert.Equal(t, "key_02", got.PublicId)
}

func Test_VaultRepository_UpdateKey_nameChange_notAllowed(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "original-name", "signature")

	renamed := NewKey(&storepb.Key{
		PublicId:       "key_01",
		Name:           "new-name",
		Primitive:      "signature",
		Status:         storepb.KeyStatus_KEY_STATUS_ACTIVE,
		CurrentVersion: 1,
	})
	err := r.UpdateKey(ctx, renamed)
	require.Error(t, err)
	require.True(t, errors.IsInvalidArgument(err), "expected InvalidArgument for name change, got: %v", err)
}

func Test_VaultRepository_GetKeyByName_afterAddVersion_returnsUpdatedCurrentVersion(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "my-key", "signature")

	v2, err := newVersion(ctx, defaultKeyVersionID("key_01", 2), "key_01", "template", "software", 2, []byte("key-v2-bytes"), WithStatus(storepb.KeyStatus_KEY_STATUS_ACTIVE))
	require.NoError(t, err)
	require.NoError(t, r.AddVersion(ctx, v2))

	got, err := r.GetKeyByName(ctx, "my-key")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), got.CurrentVersion)

	current, err := r.GetCurrentVersion(ctx, got.PublicId)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), current.Version)
}

func Test_VaultRepository_GetCurrentVersion(t *testing.T) {
	testCases := []struct {
		keyID              string
		additionalVersions int
	}{
		{"key_01", 1},
		{"key_02", 3},
		{"key_03", 25},
	}
	r := repoFn()
	for _, tc := range testCases {
		t.Run(tc.keyID, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			km := []byte("fake-key-bytes")
			k, v := mustNewCreateKeyInputs(t, ctx, tc.keyID, tc.keyID, "template-id", "software", "policy-test", &core.ScopeSpec{
				Primitive: core.PrimitiveSignature,
				Scope:     core.SignatureScopeStandard,
			}, 0, km, storepb.KeyStatus_KEY_STATUS_ACTIVE)
			err := r.CreateKey(ctx, k, v, WithInitialVersion(0))
			require.NoErrorf(err, "CreateKey error for key %s: %v", tc.keyID, err)
			v0, err := r.GetCurrentVersion(ctx, tc.keyID)
			require.NoErrorf(err, "GetCurrentVersion error for key %s: %v", tc.keyID, err)
			assert.Equal(uint32(0), v0.Version, "initial version should be 0")
			for i := 1; i < tc.additionalVersions; i++ {
				nextVersion, err := newVersion(ctx, defaultKeyVersionID(tc.keyID, uint32(i)), tc.keyID, "template", "software", uint32(i), km, WithStatus(storepb.KeyStatus_KEY_STATUS_ACTIVE))
				require.NoErrorf(err, "newVersion error for version %d of key %s: %v", i, tc.keyID, err)
				err = r.AddVersion(ctx, nextVersion)
				require.NoErrorf(err, "AddVersion error for version %d of key %s: %v", i, tc.keyID, err)
				current, err := r.GetCurrentVersion(ctx, tc.keyID)
				require.NoErrorf(err, "GetCurrentVersion error after adding version %d for key %s: %v", i, tc.keyID, err)
				assert.Equal(uint32(i), current.Version, "current version should be updated to %d after adding new version", i)
			}
		})
	}
}
