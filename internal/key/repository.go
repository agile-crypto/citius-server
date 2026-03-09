package key

import "context"

// Repository defines the persistence contract for the Key aggregate.
//
// Key is the aggregate root; KeyVersion is an entity within that aggregate.
// The repository exposes aggregate-level operations - there is no way to
// create a KeyVersion without an associated Key (enforced by CreateKey).
type Repository interface {

	// CreateKey atomically persists a new Key AND its initial KeyVersion.
	// The store should assign version_number = 1, set is_current = true, and
	// populate the Key's current_version field.
	//
	// Returns CodeAlreadyExists if a key with the same PublicID already exists.
	//
	// Implementation contract:
	//   - In-memory store: single lock covers both key + version insert
	//   - SQL store: single transaction (INSERT key + INSERT version)
	//
	// This enforces the aggregate invariant: no Key can exist without at
	// least one KeyVersion.
	CreateKey(ctx context.Context, k *Key, initialVersion *KeyVersion) error

	// ── Key metadata reads ──

	// GetKey retrieves a key by public ID (metadata only, no material).
	GetKey(ctx context.Context, publicID string) (*Key, error)

	// ListKeys returns all stored keys as full domain objects.
	ListKeys(ctx context.Context) ([]*Key, error)

	// ── Key metadata updates (lifecycle, policy) ──

	// UpdateKey replaces the stored key metadata. The key must already exist.
	UpdateKey(ctx context.Context, k *Key) error

	// ── Aggregate deletion ──

	// DeleteKey removes a key AND all its associated versions (cascade).
	DeleteKey(ctx context.Context, publicID string) error

	// ── Version operations (parent Key must exist) ──
	// Only the key orchestrator calls these. External access to key material
	// goes through KeyOrchestrator.GetKeyWithMaterial(), which enforces
	// lifecycle checks (IsTerminal, CanPerformCrypto).

	// AddVersion atomically stores a new KeyVersion and increments the
	// parent Key's current_version field. The store assigns version_number
	// and sets is_current; the caller must populate all other fields
	// (version_id, key_id, material, hmac, provider_name).
	//
	// Used by RotateKey to add subsequent versions to an existing key.
	// For the first version, use CreateKey instead.
	//
	// Implementation contract:
	//   - In-memory store: hold lock across read + write
	//   - SQL store: use a transaction (SELECT FOR UPDATE + INSERT + UPDATE)
	//
	// This prevents race conditions in RotateKey/TransformKey by generating
	// the version number and updating atomically.
	AddVersion(ctx context.Context, keyName string, version *KeyVersion) error

	// GetVersion retrieves a specific version of a key by version number.
	// Pass versionNum=0 to retrieve the latest (current) version.
	GetVersion(ctx context.Context, keyName string, versionNum uint32) (*KeyVersion, error)
}
