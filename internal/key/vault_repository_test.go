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

// helper: create a key+version in the store (for tests that need setup).
func mustCreateKey(t *testing.T, r Repository, publicID, name string, scope string) {
	t.Helper()
	scopeSpec := &core.ScopeSpec{ScopeType: scope}
	if err := r.CreateKey(context.Background(), publicID, "template-id", "software", "policy-test", scopeSpec, []byte("fake-key-bytes"), WithName(name)); err != nil {
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

	scopeSpec := &core.ScopeSpec{ScopeType: "signature"}
	initialVersionNbr := uint32(1)
	if err := r.CreateKey(ctx, "key_01HXYZ", "template-id", "software", "policy-test", scopeSpec, []byte("fake-key-bytes"),
		WithName("signing-key"), WithInitialVersion(initialVersionNbr)); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := r.GetKey(ctx, "key_01HXYZ")
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
	scopeSpec := &core.ScopeSpec{ScopeType: "signature"}
	if err := r.CreateKey(ctx, "key_01HXYZ", "template-id", "software", "policy-test", scopeSpec, []byte("fake-key-bytes"), WithName("signing-key")); err != nil {
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

func Test_VaultRepository_GetKey_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetKey(context.Background(), "key_doesnotexist")
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
	scopeSpec := &core.ScopeSpec{ScopeType: "signature"}
	_ = r.CreateKey(ctx, "key_01HXYZ", "template-id", "software", "policy-test", scopeSpec, []byte("fake-key-bytes"), WithName("signing-key"))
	err := r.CreateKey(ctx, "key_01HXYZ", "template-id2", "software", "policy-test2", scopeSpec, []byte("fake-key-bytes2"), WithName("signing-key2"))
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

	got, _ := r.GetKey(ctx, "key_01HXYZ")
	got.Name = "mutated"

	got2, _ := r.GetKey(ctx, "key_01HXYZ")
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
	_, err := r.GetKey(ctx, "key_01HXYZ")
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
	if err := r.AddVersion(ctx, kid, "template", "software", []byte("key_version_1")); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	err = r.AddVersion(ctx, kid, "template", "software", []byte("key_version_2"))
	require.NoError(err, "got error when adding second version")
	k, err := r.GetKey(ctx, kid)
	require.NoErrorf(err, "error when getting key with id=%s", kid)
	assert.Equal(uint32(v2.Version+1), k.CurrentVersion, "current version should be 2")
	err = r.DeleteKey(ctx, "key_01HXYZ")
	require.NoError(err, "DeleteKey should not return error")
	_, err = r.GetKey(ctx, "key_01HXYZ")
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

	got, err := r.GetKey(ctx, "key_01HXYZ")
	if err != nil {
		t.Fatalf("GetKey after update: %v", err)
	}
	if got.GetStatus() != storepb.KeyStatus_KEY_STATUS_SUSPENDED {
		t.Errorf("status: got %v want SUSPENDED", got.GetStatus())
	}
}

func Test_VaultRepository_UpdateKey_notFound_returnsError(t *testing.T) {
	r := repoFn()
	k, err := newTestKey("id", "signing-key", &core.ScopeSpec{ScopeType: "signature"})
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

	err := r.AddVersion(ctx, "key_01", "template", "software", []byte("key_version_2"))
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

	if err := r.AddVersion(ctx, "key_01", "template", "software", []byte("key_version_2")); err != nil {
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
	err := r.AddVersion(context.Background(), "key_missing", "template", "software", []byte("key_material"))
	if err == nil {
		t.Fatal("expected error for adding version to non-existent key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

func Test_VaultRepository_GetCurrentVersion(t *testing.T) {
	testCases := []struct {
		keyId              string
		additionalVersions int
	}{
		{"key_01", 1},
		{"key_02", 3},
		{"key_03", 25},
	}
	r := repoFn()
	for _, tc := range testCases {
		t.Run(tc.keyId, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			km := []byte("fake-key-bytes")
			err := r.CreateKey(ctx, tc.keyId, "template-id", "software", "policy-test", &core.ScopeSpec{ScopeType: "signature"}, km, WithInitialVersion(0))
			require.NoErrorf(err, "CreateKey error for key %s: %v", tc.keyId, err)
			v0, err := r.GetCurrentVersion(ctx, tc.keyId)
			require.NoErrorf(err, "GetCurrentVersion error for key %s: %v", tc.keyId, err)
			assert.Equal(uint32(0), v0.Version, "initial version should be 0")
			for i := 1; i < tc.additionalVersions; i++ {
				err = r.AddVersion(ctx, tc.keyId, "template", "software", km)
				require.NoErrorf(err, "AddVersion error for version %d of key %s: %v", i, tc.keyId, err)
				current, err := r.GetCurrentVersion(ctx, tc.keyId)
				require.NoErrorf(err, "GetCurrentVersion error after adding version %d for key %s: %v", i, tc.keyId, err)
				assert.Equal(uint32(i), current.Version, "current version should be updated to %d after adding new version", i)
			}
		})
	}

}
