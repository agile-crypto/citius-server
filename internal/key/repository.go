package key

import "context"

// Repository defines the persistence contract for the Key aggregate.
type Repository interface {
	// --- Key metadata operations ---
	PutKey(ctx context.Context, k *Key) error
	GetKey(ctx context.Context, name string) (*Key, error)
	DeleteKey(ctx context.Context, name string) error
	ListKeys(ctx context.Context) ([]string, error)
	UpdateKey(ctx context.Context, k *Key) error

	// --- Key version operations ---
	// Only key.Orchestrator calls these. External access to key material
	// goes through KeyOrchestrator.GetKeyWithMaterial(), which enforces
	// lifecycle checks (IsTerminal, CanPerformCrypto).

	// CreateVersion atomically stores a new KeyVersion and increments the
	// parent Key's current_version field. The store assigns version_number
	// and sets is_current; the caller must populate all other fields
	// (version_id, key_id, material, hmac, provider_name).
	//
	// Implementation contract:
	//   - In-memory store: hold lock across read + write
	//   - SQL store: use a transaction (SELECT FOR UPDATE + INSERT + UPDATE)
	//
	// This prevents race conditions in RotateKey/TransformKey by generating
	// the version number and updating atomically.
	CreateVersion(ctx context.Context, keyName string, version *KeyVersion) error

	// GetKeyVersion retrieves a specific version of a key by version number.
	GetKeyVersion(ctx context.Context, keyName string, versionNum uint32) (*KeyVersion, error)

	// DeleteKeyVersion removes a specific version record.
	DeleteKeyVersion(ctx context.Context, keyName string, versionNum uint32) error
}
