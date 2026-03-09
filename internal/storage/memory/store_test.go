package memory_test

import (
	"context"
	"testing"

	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/crypto"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/storage"
	"github.ibm.com/citius/citius-server/internal/storage/memory"
)

// helper: create a valid Key domain object.
func newTestKey(publicID, name, templateID string) *key.Key {
	return key.New(&storepb.StoredKey{
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
func mustCreateKey(t *testing.T, store *memory.MemoryStore, publicID, name, templateID string) {
	t.Helper()
	k := newTestKey(publicID, name, templateID)
	v := newTestKeyVersion("ver_"+publicID, publicID, "software")
	if err := store.CreateKey(context.Background(), k, v); err != nil {
		t.Fatalf("mustCreateKey(%s): %v", publicID, err)
	}
}

// ============================================================================
// CreateKey / GetKey
// ============================================================================

func TestMemoryStore_CreateKey_GetKey_roundtrip(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	k := newTestKey("key_01HXYZ", "signing-key", "ecdsa-p256-sha256")
	v := newTestKeyVersion("ver_01", "key_01HXYZ", "software")

	if err := store.CreateKey(ctx, k, v); err != nil {
		t.Fatalf("CreateKey: %v", err)
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
	if got.StoredKey().GetCurrentVersion() != 1 {
		t.Errorf("CurrentVersion: got %d want 1", got.StoredKey().GetCurrentVersion())
	}
}

func TestMemoryStore_CreateKey_setsVersion1(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	k := newTestKey("key_01HXYZ", "signing-key", "ecdsa-p256-sha256")
	v := newTestKeyVersion("ver_01", "key_01HXYZ", "software")
	_ = store.CreateKey(ctx, k, v)

	got, err := store.GetVersion(ctx, "key_01HXYZ", 1)
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
	store := memory.New()
	_, err := store.GetKey(context.Background(), "key_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

func TestMemoryStore_CreateKey_duplicate_returnsError(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	k := newTestKey("key_01HXYZ", "original", "ecdsa-p256-sha256")
	v := newTestKeyVersion("ver_01", "key_01HXYZ", "software")
	_ = store.CreateKey(ctx, k, v)

	k2 := newTestKey("key_01HXYZ", "duplicate", "ecdsa-p256-sha256")
	v2 := newTestKeyVersion("ver_02", "key_01HXYZ", "software")
	err := store.CreateKey(ctx, k2, v2)
	if err == nil {
		t.Fatal("expected error for duplicate key")
	}
	if !errors.IsAlreadyExists(err) {
		t.Errorf("expected AlreadyExists, got: %v", err)
	}
}

func TestMemoryStore_CreateKey_nilKey_returnsError(t *testing.T) {
	store := memory.New()
	v := newTestKeyVersion("ver_01", "key_01", "software")
	err := store.CreateKey(context.Background(), nil, v)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestMemoryStore_CreateKey_nilVersion_returnsError(t *testing.T) {
	store := memory.New()
	k := newTestKey("key_01HXYZ", "signing-key", "ecdsa-p256-sha256")
	err := store.CreateKey(context.Background(), k, nil)
	if err == nil {
		t.Fatal("expected error for nil initialVersion")
	}
}

func TestMemoryStore_GetKey_returnsClone(t *testing.T) {
	// Mutating the returned key should NOT affect the stored copy.
	store := memory.New()
	ctx := context.Background()
	mustCreateKey(t, store, "key_01HXYZ", "original", "ecdsa-p256-sha256")

	got, _ := store.GetKey(ctx, "key_01HXYZ")
	got.StoredKey().Name = "mutated"

	got2, _ := store.GetKey(ctx, "key_01HXYZ")
	if got2.Name() != "original" {
		t.Errorf("stored key was mutated: got %q want %q", got2.Name(), "original")
	}
}

// ============================================================================
// DeleteKey (cascading)
// ============================================================================

func TestMemoryStore_DeleteKey_success(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	mustCreateKey(t, store, "key_01HXYZ", "k", "ecdsa-p256-sha256")

	if err := store.DeleteKey(ctx, "key_01HXYZ"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	_, err := store.GetKey(ctx, "key_01HXYZ")
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound after delete, got: %v", err)
	}
}

func TestMemoryStore_DeleteKey_cascadesVersions(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	mustCreateKey(t, store, "key_01HXYZ", "k", "ecdsa-p256-sha256")
	// Add a second version so we verify both are cleaned up.
	_ = store.AddVersion(ctx, "key_01HXYZ", newTestKeyVersion("ver_02", "key_01HXYZ", "software"))

	if err := store.DeleteKey(ctx, "key_01HXYZ"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	// Both versions should be gone.
	_, err := store.GetVersion(ctx, "key_01HXYZ", 1)
	if err == nil {
		t.Error("expected error fetching version 1 after cascading delete")
	}
	_, err = store.GetVersion(ctx, "key_01HXYZ", 2)
	if err == nil {
		t.Error("expected error fetching version 2 after cascading delete")
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
	mustCreateKey(t, store, "key_01", "k1", "ecdsa-p256-sha256")
	mustCreateKey(t, store, "key_02", "k2", "ml-dsa-65")

	keys, err := store.ListKeys(ctx)
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
	store := memory.New()
	ctx := context.Background()
	mustCreateKey(t, store, "key_01", "k1", "ecdsa-p256-sha256")
	mustCreateKey(t, store, "key_02", "k2", "ml-dsa-65")
	mustCreateKey(t, store, "key_03", "k3", "ecdsa-p256-sha256")

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
	mustCreateKey(t, store, "key_01HXYZ", "signing-key", "ecdsa-p256-sha256")

	// Build an updated Key with new status.
	updated := key.New(&storepb.StoredKey{
		PublicId:       "key_01HXYZ",
		Name:           "signing-key",
		TemplateId:     "ecdsa-p256-sha256",
		Status:         storepb.KeyStatus_KEY_STATUS_SUSPENDED,
		CurrentVersion: 1,
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
// AddVersion / GetVersion
// ============================================================================

func TestMemoryStore_AddVersion_GetVersion_roundtrip(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	mustCreateKey(t, store, "key_01", "k", "ecdsa-p256-sha256")

	v2 := newTestKeyVersion("ver_02", "key_01", "software")
	if err := store.AddVersion(ctx, "key_01", v2); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	got, err := store.GetVersion(ctx, "key_01", 2)
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
	store := memory.New()
	ctx := context.Background()
	mustCreateKey(t, store, "key_01", "k", "ecdsa-p256-sha256")

	v2 := newTestKeyVersion("ver_02", "key_01", "software")
	if err := store.AddVersion(ctx, "key_01", v2); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	got, err := store.GetVersion(ctx, "key_01", 1)
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
	store := memory.New()
	_, err := store.GetVersion(context.Background(), "key_01", 99)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound error, got: %v", err)
	}
}

func TestMemoryStore_AddVersion_returnsClone(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	mustCreateKey(t, store, "key_01", "k", "ecdsa-p256-sha256")

	// Fetch version 1 (created by CreateKey) and mutate the returned clone.
	got, _ := store.GetVersion(ctx, "key_01", 1)
	got.StoredKeyVersion().ProviderName = "mutated"

	// Re-fetch — should still have original value.
	got2, _ := store.GetVersion(ctx, "key_01", 1)
	if got2.StoredKeyVersion().GetProviderName() != "software" {
		t.Error("GetVersion should return a clone — stored value was mutated")
	}
}

func TestMemoryStore_AddVersion_assignsIncrementingVersionNumber(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	mustCreateKey(t, store, "key_01", "k", "ecdsa-p256-sha256") // creates version 1

	_ = store.AddVersion(ctx, "key_01", newTestKeyVersion("ver_02", "key_01", "software"))
	_ = store.AddVersion(ctx, "key_01", newTestKeyVersion("ver_03", "key_01", "software"))

	v3, err := store.GetVersion(ctx, "key_01", 3)
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
	v2, _ := store.GetVersion(ctx, "key_01", 2)
	if v2.StoredKeyVersion().GetIsCurrent() {
		t.Error("version 2 should not be marked is_current after version 3 added")
	}
}

func TestMemoryStore_AddVersion_keyNotFound_returnsError(t *testing.T) {
	store := memory.New()
	v := newTestKeyVersion("ver_01", "key_missing", "software")
	err := store.AddVersion(context.Background(), "key_missing", v)
	if err == nil {
		t.Fatal("expected error for adding version to non-existent key")
	}
	if !errors.IsKeyNotFound(err) {
		t.Errorf("expected KeyNotFound, got: %v", err)
	}
}

// ============================================================================
// Policy storage operations
// ============================================================================
func newTestPolicy(publicID, name string) *policy.Policy {
	return policy.New(&storepb.StoredPolicy{
		PublicId: publicID,
		Name:     name,
	})
}

func TestMemoryStore_PutPolicy_GetPolicy_roundtrip(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	p := newTestPolicy("pol_01", "default-sig-policy")

	if err := store.PutPolicy(ctx, p); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	got, err := store.GetPolicy(ctx, "pol_01")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.Name() != "default-sig-policy" {
		t.Errorf("Name: got %q want %q", got.Name(), "default-sig-policy")
	}
}

func TestMemoryStore_GetPolicy_notFound(t *testing.T) {
	store := memory.New()
	_, err := store.GetPolicy(context.Background(), "pol_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing policy")
	}
	if !errors.IsPolicyNotFound(err) {
		t.Errorf("expected PolicyNotFound, got: %v", err)
	}
}

func TestMemoryStore_DeletePolicy_success(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	_ = store.PutPolicy(ctx, newTestPolicy("pol_01", "p"))
	if err := store.DeletePolicy(ctx, "pol_01"); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	_, err := store.GetPolicy(ctx, "pol_01")
	if !errors.IsPolicyNotFound(err) {
		t.Errorf("expected PolicyNotFound after delete, got: %v", err)
	}
}

func TestMemoryStore_ListPolicies_all(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	_ = store.PutPolicy(ctx, newTestPolicy("pol_01", "p1"))
	_ = store.PutPolicy(ctx, newTestPolicy("pol_02", "p2"))

	policyIDs, err := store.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(policyIDs) != 2 {
		t.Errorf("ListPolicies: got %d want 2", len(policyIDs))
	}
}

func TestMemoryStore_ListPolicies_empty(t *testing.T) {
	store := memory.New()
	policyIDs, err := store.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if policyIDs == nil {
		t.Error("ListPolicies should return empty slice, not nil")
	}
}

func TestMemoryStore_GetPolicy_returnsClone(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	_ = store.PutPolicy(ctx, newTestPolicy("pol_01", "original"))
	got, _ := store.GetPolicy(ctx, "pol_01")
	got.StoredPolicy().Name = "mutated"
	got2, _ := store.GetPolicy(ctx, "pol_01")
	if got2.Name() != "original" {
		t.Error("GetPolicy should return a clone")
	}
}

// ============================================================================
// ProviderInstance storage operations
// ============================================================================

func newTestProviderInstance(publicID, name, provType string) *provider.Instance {
	return provider.NewInstance(&storepb.StoredProviderInstance{
		PublicId:     publicID,
		Name:         name,
		ProviderType: provType,
	})
}

func TestMemoryStore_PutProviderInstance_Get_roundtrip(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	pi := newTestProviderInstance("prv_01", "software-default", "software")

	if err := store.PutProviderInstance(ctx, pi); err != nil {
		t.Fatalf("PutProviderInstance: %v", err)
	}
	got, err := store.GetProviderInstance(ctx, "prv_01")
	if err != nil {
		t.Fatalf("GetProviderInstance: %v", err)
	}
	if got.StoredProviderInstance().GetName() != "software-default" {
		t.Errorf("Name: got %q want %q", got.StoredProviderInstance().GetName(), "software-default")
	}
}

func TestMemoryStore_GetProviderInstance_notFound(t *testing.T) {
	store := memory.New()
	_, err := store.GetProviderInstance(context.Background(), "prv_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing provider instance")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound, got: %v", err)
	}
}

func TestMemoryStore_ListProviderInstances(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	_ = store.PutProviderInstance(ctx, newTestProviderInstance("prv_01", "sw1", "software"))
	_ = store.PutProviderInstance(ctx, newTestProviderInstance("prv_02", "sw2", "software"))

	piIDs, err := store.ListProviderInstances(ctx)
	if err != nil {
		t.Fatalf("ListProviderInstances: %v", err)
	}
	if len(piIDs) != 2 {
		t.Errorf("ListProviderInstances: got %d want 2", len(piIDs))
	}
}

// ============================================================================
// Session storage operations
// ============================================================================

func newTestSession(publicID, keyID string) *crypto.Session {
	return crypto.NewSession(&storepb.StoredSession{
		PublicId:  publicID,
		KeyId:     keyID,
		Operation: "sign",
		Status:    storepb.SessionStatus_SESSION_STATUS_ACTIVE,
	})
}

func TestMemoryStore_PutSession_GetSession_roundtrip(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	s := newTestSession("ses_01", "key_01")

	if err := store.PutSession(ctx, s); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	got, err := store.GetSession(ctx, "ses_01")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.StoredSession().GetKeyId() != "key_01" {
		t.Errorf("KeyId: got %q want %q", got.StoredSession().GetKeyId(), "key_01")
	}
}

func TestMemoryStore_GetSession_notFound(t *testing.T) {
	store := memory.New()
	_, err := store.GetSession(context.Background(), "ses_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing session")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound, got: %v", err)
	}
}

func TestMemoryStore_DeleteSession_success(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	_ = store.PutSession(ctx, newTestSession("ses_01", "key_01"))
	if err := store.DeleteSession(ctx, "ses_01"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	_, err := store.GetSession(ctx, "ses_01")
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound after delete, got: %v", err)
	}
}

// ============================================================================
// Compile-time assertion
// ============================================================================
var _ storage.Storage = (*memory.MemoryStore)(nil)
