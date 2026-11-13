// Package key builds the key repository over a Vault logical.Storage.
//
// The repository itself lives in internal/storage/key and depends only on
// storage.Storage; this package adapts the Vault storage and delegates.
package key

import (
	"context"

	storagekey "github.com/agile-crypto/citius-server/internal/storage/key"
	"github.com/agile-crypto/citius-server/vault-storage/vaultlogical"
	"github.com/hashicorp/vault/sdk/logical"
)

type (
	// VaultRepository is the key repository built by NewVaultRepository.
	VaultRepository = storagekey.VaultRepository
	// VaultRepositoryOption configures NewVaultRepository.
	VaultRepositoryOption = storagekey.VaultRepositoryOption
)

// NewVaultRepository returns a key repository backed by the given Vault
// storage.
func NewVaultRepository(ctx context.Context, s logical.Storage, opt ...VaultRepositoryOption) (*VaultRepository, error) {
	return storagekey.NewVaultRepository(ctx, vaultlogical.FromLogical(s), opt...)
}
