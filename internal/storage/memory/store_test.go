package memory_test

import (
	"context"
	"testing"

	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/storage/memory"
)

// helper: create a valid Key domain object
func newTestKey(publicID, name, templateID string) *key.Key {
	return key.New(&storepb.StoredKey{
		PublicId:   publicID,
		Name:       name,
		TemplateId: templateID,
		Status:     storepb.KeyStatus_KEY_STATUS_ACTIVE,
	})
}

// ============================================================================
// PutKey / GetKey
// ============================================================================

func TestMemoryStore_PutKey_GetKey_roundtrip(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	key := newTestKey("key_01HXYZ", "signing-key", "ecdsa-p256-sha256")

	if err := store.PutKey(ctx, key); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	got, err := store.GetKey(ctx, "key_01HXYZ")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.PublicID() != "key_01HXYZ" {
		t.Errorf("PublicID: got %q want %q", got.PublicID(), "key_01HXYZ")
	}
	if got.Name() != "signing-key" {
		t.Errorf("Name: got %q want %q", got.Name(), "signing-key")
	}
}

func TestMemoryStore_GetKey_notFound(t *testing.T) {
	store := memory.New()
	_, err := store.GetKey(context.Background(), "key_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

func TestMemoryStore_PutKey_overwrite(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	k1 := newTestKey("key_01HXYZ", "original", "ecdsa-p256-sha256")
	k2 := newTestKey("key_01HXYZ", "updated", "ecdsa-p256-sha256")

	_ = store.PutKey(ctx, k1)
	_ = store.PutKey(ctx, k2)

	got, err := store.GetKey(ctx, "key_01HXYZ")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.Name() != "updated" {
		t.Errorf("Name: got %q want %q", got.Name(), "updated")
	}
}

func TestMemoryStore_PutKey_nilKey_returnsError(t *testing.T) {
	store := memory.New()
	err := store.PutKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestMemoryStore_GetKey_returnsClone(t *testing.T) {
	// Mutating the returned key should NOT affect the stored copy.
	store := memory.New()
	ctx := context.Background()
	k := newTestKey("key_01HXYZ", "original", "ecdsa-p256-sha256")
	_ = store.PutKey(ctx, k)

	got, _ := store.GetKey(ctx, "key_01HXYZ")
	got.StoredKey().Name = "mutated"

	got2, _ := store.GetKey(ctx, "key_01HXYZ")
	if got2.Name() != "original" {
		t.Errorf("stored key was mutated: got %q want %q", got2.Name(), "original")
	}
}

// ============================================================================
// DeleteKey
// ============================================================================

func TestMemoryStore_DeleteKey_success(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	_ = store.PutKey(ctx, newTestKey("key_01HXYZ", "k", "ecdsa-p256-sha256"))
	if err := store.DeleteKey(ctx, "key_01HXYZ"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	_, err := store.GetKey(ctx, "key_01HXYZ")
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound after delete, got: %v", err)
	}
}

func TestMemoryStore_DeleteKey_notFound_returnsError(t *testing.T) {
	store := memory.New()
	err := store.DeleteKey(context.Background(), "key_doesnotexist")
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
	store := memory.New()
	ctx := context.Background()
	_ = store.PutKey(ctx, newTestKey("key_01", "k1", "ecdsa-p256-sha256"))
	_ = store.PutKey(ctx, newTestKey("key_02", "k2", "ml-dsa-65"))

	keys, err := store.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("ListKeys: got %d want 2", len(keys))
	}
}

func TestMemoryStore_ListKeys_multipleKeys(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	_ = store.PutKey(ctx, newTestKey("key_01", "k1", "ecdsa-p256-sha256"))
	_ = store.PutKey(ctx, newTestKey("key_02", "k2", "ml-dsa-65"))
	_ = store.PutKey(ctx, newTestKey("key_03", "k3", "ecdsa-p256-sha256"))

	keys, err := store.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("ListKeys: got %d want 3", len(keys))
	}
}

func TestMemoryStore_ListKeys_empty(t *testing.T) {
	store := memory.New()
	keys, err := store.ListKeys(context.Background())
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
	store := memory.New()
	ctx := context.Background()
	k := newTestKey("key_01HXYZ", "signing-key", "ecdsa-p256-sha256")
	_ = store.PutKey(ctx, k)

	// Build an updated Key with new status
	updated := key.New(&storepb.StoredKey{
		PublicId:   "key_01HXYZ",
		Name:       "signing-key",
		TemplateId: "ecdsa-p256-sha256",
		Status:     storepb.KeyStatus_KEY_STATUS_SUSPENDED,
	})
	if err := store.UpdateKey(ctx, updated); err != nil {
		t.Fatalf("UpdateKey: %v", err)
	}

	got, err := store.GetKey(ctx, "key_01HXYZ")
	if err != nil {
		t.Fatalf("GetKey after update: %v", err)
	}
	if got.StoredKey().GetStatus() != storepb.KeyStatus_KEY_STATUS_SUSPENDED {
		t.Errorf("status: got %v want SUSPENDED", got.StoredKey().GetStatus())
	}
}

func TestMemoryStore_UpdateKey_notFound_returnsError(t *testing.T) {
	store := memory.New()
	k := newTestKey("key_missing", "signing-key", "ecdsa-p256-sha256")
	err := store.UpdateKey(context.Background(), k)
	if err == nil {
		t.Fatal("expected error for updating non-existent key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

func TestMemoryStore_UpdateKey_nil_returnsError(t *testing.T) {
	store := memory.New()
	err := store.UpdateKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

// ============================================================================
// Compile-time assertion
// ============================================================================

// Note: the full Storage interface is NOT satisfied yet - only the key-related methods implemented so far.
// TODO:  Uncomment this assertion only after those steps are complete.
//var _ storage.Storage = (*memory.MemoryStore)(nil)
