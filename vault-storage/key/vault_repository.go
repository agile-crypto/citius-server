// Package key builds the key repository over a Vault logical.Storage.
//
// The repository itself lives in internal/storage/key and depends only on
// storage.Storage; this package adapts the Vault storage and delegates.
package key

import (
	"context"

	"github.com/agile-crypto/citius-core/key"
	"github.com/agile-crypto/citius-server/vault-storage/vaultlogical"
	"github.com/hashicorp/vault/sdk/logical"
)

type (
	// VaultRepository is the key repository built by NewVaultRepository.
	VaultRepository = key.StorageRepository
	// VaultRepositoryOption configures NewVaultRepository.
	VaultRepositoryOption = key.RepoOptions
)

// NewVaultRepository returns a key repository backed by the given Vault
// storage.
func NewVaultRepository(ctx context.Context, s logical.Storage, opt ...key.Option) (*VaultRepository, error) {
	return key.NewStorageRepository(ctx, vaultlogical.FromLogical(s), opt...)
}
