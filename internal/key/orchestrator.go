package key

import (
	"context"

	"github.ibm.com/citius/citius-server/internal/core"
)

// Orchestrator orchestrates key lifecycle.
// Implementations coordinate template selection, provider dispatch, policy validation,
// and repository persistence.
type Orchestrator interface {
	CreateKey(ctx context.Context, spec core.KeyCreationSpec) (*Key, error)
	ReadKey(ctx context.Context, name string) (*Key, error)
	ListKeys(ctx context.Context) ([]*Key, error)
	DeleteKey(ctx context.Context, name string) error

	// GetKeyWithMaterial fetches the key AND a specific version's material.
	// Used internally by crypto.Orchestrator — not exposed over gRPC directly.
	// Pass version=0 for latest version.
	GetKeyWithMaterial(ctx context.Context, name string, version uint32) (*Key, *KeyVersion, error)

	RotateKey(ctx context.Context, name string) (*Key, error)
	SuspendKey(ctx context.Context, name string) error
	RestoreKey(ctx context.Context, name string) error
	DestroyKey(ctx context.Context, name string) error

	ImportKey(ctx context.Context, spec core.ImportKeySpec) (*Key, error)

	// UpdateKeyPolicy changes the policy governing an existing key.
	// Policy changes take effect on the next crypto operation — no re-encryption needed.
	// Returns ErrNotFound if the key does not exist.
	UpdateKeyPolicy(ctx context.Context, name string, policyName string) error
}
