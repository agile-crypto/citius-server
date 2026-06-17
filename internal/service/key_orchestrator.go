package service

import (
	"context"

	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/key"
)

// KeyOrchestrator orchestrates key lifecycle workflows.
// Implementations coordinate template selection, provider dispatch, policy validation,
// and repository persistence crossing aggregate boundaries.
type KeyOrchestrator interface {
	CreateKey(ctx context.Context, spec core.KeyCreationSpec) (*KeyMetadata, error)
	ReadKey(ctx context.Context, keyName string) (*KeyMetadata, error)
	ListKeys(ctx context.Context) ([]*KeyMetadata, error)
	DeleteKey(ctx context.Context, keyName string) error

	// GetKeyWithMaterial fetches the key AND a specific version's material.
	// Used internally by CryptoOrchestrator — not exposed over gRPC directly.
	// Pass version=0 for latest version.
	GetKeyWithMaterial(ctx context.Context, keyName string, version uint32) (*key.Key, *key.Version, error)

	RotateKey(ctx context.Context, keyName string) (*KeyMetadata, error)
	SuspendKey(ctx context.Context, keyName string) error
	RestoreKey(ctx context.Context, keyName string) error
	DestroyKey(ctx context.Context, keyName string) error

	ImportKey(ctx context.Context, spec core.ImportKeySpec) (*KeyMetadata, error)

	// UpdateKeyPolicy changes the policy governing an existing key.
	// Policy changes take effect on the next crypto operation.
	// Returns ErrNotFound if the key does not exist.
	UpdateKeyPolicy(ctx context.Context, keyName string, policyName string) error
}
