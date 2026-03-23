package key

import (
	"context"

	"github.ibm.com/citius/citius-server/internal/core"
)

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
	// Allowed options:
	CreateKey(ctx context.Context, id string, templateId, providerId, policyId string, scopeSpecification *core.ScopeSpec, keyMaterial []byte, opt ...Option) error

	// ── Key metadata reads ──

	// GetKey retrieves a key by public ID (metadata only, no material).
	GetKey(ctx context.Context, id string) (*Key, error)

	// ListKeys returns all stored keys as full domain objects.
	ListKeys(ctx context.Context) ([]*Key, error)

	// ── Key metadata updates (lifecycle, policy) ──

	// UpdateKey replaces the stored key metadata. The key must already exist.
	UpdateKey(ctx context.Context, k *Key, opt ...Option) error

	// ── Aggregate deletion ──

	// DeleteKey removes a key AND all its associated versions (cascade).
	DeleteKey(ctx context.Context, id string) error

	// ── Version operations (parent Key must exist) ──
	// Only the key orchestrator calls these. External access to key material
	// goes through KeyOrchestrator.GetKeyWithMaterial(), which enforces
	// lifecycle checks (IsTerminal, CanPerformCrypto).

	// AddVersion atomically creates and stores a new key version, and increments the
	// parent Key's current_version field. The new version's version number is equal
	// to the parent Key's previous current_version + 1.
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
	//   - withPublicId (optional): if not set, generated
	//   - withStatus (optional): if not set, defaults to ACTIVE
	//   - withWrappingKeyId (optional): if not set, defaults to default storage wrapping key
	//   - withDigestAlgorthm (optional): if not set, defaults to HMAC-SHA256
	AddVersion(ctx context.Context, keyId string, templateId, providerId string, keyMaterial []byte, opt ...Option) error

	// GetVersion retrieves a specific version of a key by version number.
	GetVersion(ctx context.Context, keyId string, versionNum uint32) (*KeyVersion, error)

	// Retrieves the current version of a key by public ID.
	GetCurrentVersion(ctx context.Context, keyId string) (*KeyVersion, error)
}
