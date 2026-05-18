package key

import (
	"context"
)

// Repository defines the persistence contract for the Key aggregate.
//
// Key is the aggregate root; Version is an entity within that aggregate.
// The repository exposes aggregate-level operations - there is no way to
// create a Version without an associated Key (enforced by CreateKey).
type Repository interface {

	// Atomically persists a key along with its initial current version in storage. The
	// version number of the initial version must match the current version of the key.
	//
	// Returns CodeAlreadyExists if a key with the same PublicID already exists.
	//
	// Implementation contract:
	//   - In-memory store: single lock covers both key + version insert
	//   - SQL store: single transaction (INSERT key + INSERT version)
	//
	// This enforces the aggregate invariant: no Key can exist without at
	// least one Version.
	//
	// Allowed options:
	//   - withVetForWrite (optional): defaults to true
	CreateKey(ctx context.Context, key *Key, initialVersion *Version, opt ...Option) error

	// ── Key metadata reads ──

	// GetKeyById retrieves a key by public ID (metadata only, no material).
	GetKeyById(ctx context.Context, id string) (*Key, error)

	// GetKeyByName retrieves a key by name (metadata only, no material).
	GetKeyByName(ctx context.Context, name string) (*Key, error)

	// ListKeys returns all stored keys as full domain objects.
	ListKeys(ctx context.Context) ([]*Key, error)

	// ── Key metadata updates (lifecycle, policy) ──

	// UpdateKey replaces the stored key metadata. The key must already exist.
	UpdateKey(ctx context.Context, k *Key, opt ...Option) error

	// ── Aggregate deletion ──

	// DeleteKey removes a key AND all its associated versions (cascade).
	DeleteKey(ctx context.Context, id string) error

	// ── Version operations (parent Key must exist) ──
	// Stores a key version. The parent key must already exist. By default,
	// this current version will be set to be the new current version of the parent
	// key. The version number must be exactly 1 greater than the current
	// version of the parent key.
	//
	// Only the key orchestrator calls these. External access to key material
	// goes through KeyOrchestrator.GetKeyWithMaterial(), which enforces
	// lifecycle checks (IsTerminal, CanPerformCrypto).
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
	//
	// Allowed options:
	//   - withVetForWrite (optional): defaults to true
	AddVersion(ctx context.Context, version *Version, opt ...Option) error

	// GetVersion retrieves a specific version of a key by version number.
	GetVersion(ctx context.Context, keyID string, versionNum uint32) (*Version, error)

	// Retrieves the current version of a key by public ID.
	GetCurrentVersion(ctx context.Context, keyID string) (*Version, error)
}
