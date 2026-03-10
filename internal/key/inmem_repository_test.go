package key_test

import (
	"context"
	"testing"

	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/storage"
)

// helper: create a valid Key domain object.
func newTestKey(publicID, name, templateID string) *key.Key {
	return key.NewKey(&storepb.StoredKey{
		PublicId:   publicID,
		Name:       name,
		TemplateId: templateID,
		Status:     storepb.KeyStatus_KEY_STATUS_ACTIVE,
	})
}

// helper: create a valid KeyVersion domain object.
func newTestKeyVersion(versionID, keyID string, providerName string) *key.KeyVersion {
	return key.NewVersion(&storepb.StoredKeyVersion{
		VersionId:         versionID,
		KeyId:             keyID,
		ProviderName:      providerName,
		PlaintextMaterial: []byte("fake-key-bytes"),
		Hmac:              []byte("fake-hmac"),
		PublicKeyBytes:    []byte("fake-pub-key"),
	})
}

// helper: create a key+version in the store (for tests that need setup).
func mustCreateKey(t *testing.T, r *key.InMemRepository, publicID, name, templateID string) {
	t.Helper()
	k := newTestKey(publicID, name, templateID)
	v := newTestKeyVersion("ver_"+publicID, publicID, "software")
	if err := r.CreateKey(context.Background(), k, v); err != nil {
		t.Fatalf("mustCreateKey(%s): %v", publicID, err)
	}
}

var repoFn = func() *key.InMemRepository {
	keys := storage.NewInMemoryStorage[*key.Key]()
	keyVersions := storage.NewInMemoryStorage[map[uint32]*key.KeyVersion]()
	return key.NewInMemoryRepository(keys, keyVersions)
}

// ============================================================================
// CreateKey / GetKey
// ============================================================================

func TestMemoryStore_CreateKey_GetKey_roundtrip(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	k := newTestKey("key_01HXYZ", "signing-key", "ecdsa-p256-sha256")
	v := newTestKeyVersion("ver_01", "key_01HXYZ", "software")

	if err := r.CreateKey(ctx, k, v); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := r.GetKey(ctx, "key_01HXYZ")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.PublicID() != "key_01HXYZ" {
		t.Errorf("PublicID: got %q want %q", got.PublicID(), "key_01HXYZ")
	}
	if got.Name() != "signing-key" {
		t.Errorf("Name: got %q want %q", got.Name(), "signing-key")
	}
	if got.StoredKey().GetCurrentVersion() != 1 {
		t.Errorf("CurrentVersion: got %d want 1", got.StoredKey().GetCurrentVersion())
	}
}

func TestMemoryStore_CreateKey_setsVersion1(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	k := newTestKey("key_01HXYZ", "signing-key", "ecdsa-p256-sha256")
	v := newTestKeyVersion("ver_01", "key_01HXYZ", "software")
	_ = r.CreateKey(ctx, k, v)

	got, err := r.GetVersion(ctx, "key_01HXYZ", 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if got.StoredKeyVersion().GetVersionNumber() != 1 {
		t.Errorf("VersionNumber: got %d want 1", got.StoredKeyVersion().GetVersionNumber())
	}
	if !got.StoredKeyVersion().GetIsCurrent() {
		t.Error("initial version should be marked is_current")
	}
}

func TestMemoryStore_GetKey_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetKey(context.Background(), "key_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

func TestMemoryStore_CreateKey_duplicate_returnsError(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	k := newTestKey("key_01HXYZ", "original", "ecdsa-p256-sha256")
	v := newTestKeyVersion("ver_01", "key_01HXYZ", "software")
	_ = r.CreateKey(ctx, k, v)

	k2 := newTestKey("key_01HXYZ", "duplicate", "ecdsa-p256-sha256")
	v2 := newTestKeyVersion("ver_02", "key_01HXYZ", "software")
	err := r.CreateKey(ctx, k2, v2)
	if err == nil {
		t.Fatal("expected error for duplicate key")
	}
	if !errors.IsAlreadyExists(err) {
		t.Errorf("expected AlreadyExists, got: %v", err)
	}
}

func TestMemoryStore_CreateKey_nilKey_returnsError(t *testing.T) {
	r := repoFn()
	v := newTestKeyVersion("ver_01", "key_01", "software")
	err := r.CreateKey(context.Background(), nil, v)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestMemoryStore_CreateKey_nilVersion_returnsError(t *testing.T) {
	r := repoFn()
	k := newTestKey("key_01HXYZ", "signing-key", "ecdsa-p256-sha256")
	err := r.CreateKey(context.Background(), k, nil)
	if err == nil {
		t.Fatal("expected error for nil initialVersion")
	}
}

func TestMemoryStore_GetKey_returnsClone(t *testing.T) {
	// Mutating the returned key should NOT affect the stored copy.
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01HXYZ", "original", "ecdsa-p256-sha256")

	got, _ := r.GetKey(ctx, "key_01HXYZ")
	got.StoredKey().Name = "mutated"

	got2, _ := r.GetKey(ctx, "key_01HXYZ")
	if got2.Name() != "original" {
		t.Errorf("stored key was mutated: got %q want %q", got2.Name(), "original")
	}
}

// ============================================================================
// DeleteKey (cascading)
// ============================================================================

func TestMemoryStore_DeleteKey_success(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01HXYZ", "k", "ecdsa-p256-sha256")

	if err := r.DeleteKey(ctx, "key_01HXYZ"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	_, err := r.GetKey(ctx, "key_01HXYZ")
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound after delete, got: %v", err)
	}
}

func TestMemoryStore_DeleteKey_cascadesVersions(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01HXYZ", "k", "ecdsa-p256-sha256")
	// Add a second version so we verify both are cleaned up.
	_ = r.AddVersion(ctx, "key_01HXYZ", newTestKeyVersion("ver_02", "key_01HXYZ", "software"))

	if err := r.DeleteKey(ctx, "key_01HXYZ"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	// Both versions should be gone.
	_, err := r.GetVersion(ctx, "key_01HXYZ", 1)
	if err == nil {
		t.Error("expected error fetching version 1 after cascading delete")
	}
	_, err = r.GetVersion(ctx, "key_01HXYZ", 2)
	if err == nil {
		t.Error("expected error fetching version 2 after cascading delete")
	}
}

func TestMemoryStore_DeleteKey_notFound_returnsError(t *testing.T) {
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

func TestMemoryStore_ListKeys_all(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k1", "ecdsa-p256-sha256")
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
		if k.PublicID() == "" {
			t.Error("ListKeys returned key with empty PublicID")
		}
	}
}

func TestMemoryStore_ListKeys_multipleKeys(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k1", "ecdsa-p256-sha256")
	mustCreateKey(t, r, "key_02", "k2", "ml-dsa-65")
	mustCreateKey(t, r, "key_03", "k3", "ecdsa-p256-sha256")

	keys, err := r.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("ListKeys: got %d want 3", len(keys))
	}
}

func TestMemoryStore_ListKeys_empty(t *testing.T) {
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

func TestMemoryStore_UpdateKey_success(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01HXYZ", "signing-key", "ecdsa-p256-sha256")

	// Build an updated Key with new status.
	updated := key.NewKey(&storepb.StoredKey{
		PublicId:       "key_01HXYZ",
		Name:           "signing-key",
		TemplateId:     "ecdsa-p256-sha256",
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
	if got.StoredKey().GetStatus() != storepb.KeyStatus_KEY_STATUS_SUSPENDED {
		t.Errorf("status: got %v want SUSPENDED", got.StoredKey().GetStatus())
	}
}

func TestMemoryStore_UpdateKey_notFound_returnsError(t *testing.T) {
	r := repoFn()
	k := newTestKey("key_missing", "signing-key", "ecdsa-p256-sha256")
	err := r.UpdateKey(context.Background(), k)
	if err == nil {
		t.Fatal("expected error for updating non-existent key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

func TestMemoryStore_UpdateKey_nil_returnsError(t *testing.T) {
	r := repoFn()
	err := r.UpdateKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

// ============================================================================
// AddVersion / GetVersion
// ============================================================================

func TestMemoryStore_AddVersion_GetVersion_roundtrip(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k", "ecdsa-p256-sha256")

	v2 := newTestKeyVersion("ver_02", "key_01", "software")
	if err := r.AddVersion(ctx, "key_01", v2); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	got, err := r.GetVersion(ctx, "key_01", 2)
	if err != nil {
		t.Fatalf("GetVersion(2): %v", err)
	}
	if got.StoredKeyVersion().GetVersionId() != "ver_02" {
		t.Errorf("VersionId: got %q want %q", got.StoredKeyVersion().GetVersionId(), "ver_02")
	}
	if got.StoredKeyVersion().GetVersionNumber() != 2 {
		t.Errorf("VersionNumber: got %d want 2", got.StoredKeyVersion().GetVersionNumber())
	}
}

func TestMemoryStore_AddVersion_GetOldVersion(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k", "ecdsa-p256-sha256")

	v2 := newTestKeyVersion("ver_02", "key_01", "software")
	if err := r.AddVersion(ctx, "key_01", v2); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	got, err := r.GetVersion(ctx, "key_01", 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if got.StoredKeyVersion().GetVersionNumber() != 1 {
		t.Errorf("VersionNumber: got %d want 1", got.StoredKeyVersion().GetVersionNumber())
	}
	if got.StoredKeyVersion().GetVersionNumber() != 1 {
		t.Errorf("VersionNumber: got %d want 1", got.StoredKeyVersion().GetVersionNumber())
	}
}

func TestMemoryStore_GetVersion_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetVersion(context.Background(), "key_01", 99)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound error, got: %v", err)
	}
}

func TestMemoryStore_AddVersion_returnsClone(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k", "ecdsa-p256-sha256")

	// Fetch version 1 (created by CreateKey) and mutate the returned clone.
	got, _ := r.GetVersion(ctx, "key_01", 1)
	got.StoredKeyVersion().ProviderName = "mutated"

	// Re-fetch — should still have original value.
	got2, _ := r.GetVersion(ctx, "key_01", 1)
	if got2.StoredKeyVersion().GetProviderName() != "software" {
		t.Error("GetVersion should return a clone — stored value was mutated")
	}
}

func TestMemoryStore_AddVersion_assignsIncrementingVersionNumber(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	mustCreateKey(t, r, "key_01", "k", "ecdsa-p256-sha256") // creates version 1

	_ = r.AddVersion(ctx, "key_01", newTestKeyVersion("ver_02", "key_01", "software"))
	_ = r.AddVersion(ctx, "key_01", newTestKeyVersion("ver_03", "key_01", "software"))

	v3, err := r.GetVersion(ctx, "key_01", 3)
	if err != nil {
		t.Fatalf("GetVersion(3): %v", err)
	}
	if v3.StoredKeyVersion().GetVersionNumber() != 3 {
		t.Errorf("VersionNumber: got %d want 3", v3.StoredKeyVersion().GetVersionNumber())
	}
	if !v3.StoredKeyVersion().GetIsCurrent() {
		t.Error("latest version should be marked is_current")
	}

	// Previous version should no longer be current.
	v2, _ := r.GetVersion(ctx, "key_01", 2)
	if v2.StoredKeyVersion().GetIsCurrent() {
		t.Error("version 2 should not be marked is_current after version 3 added")
	}
}

func TestMemoryStore_AddVersion_keyNotFound_returnsError(t *testing.T) {
	r := repoFn()
	v := newTestKeyVersion("ver_01", "key_missing", "software")
	err := r.AddVersion(context.Background(), "key_missing", v)
	if err == nil {
		t.Fatal("expected error for adding version to non-existent key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}
