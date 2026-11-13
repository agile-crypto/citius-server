// Package provider builds the provider-instance repository over a Vault
// logical.Storage.
//
// The repository itself lives in internal/storage/provider and depends only
// on storage.Storage; this package adapts the Vault storage and delegates.
package provider

import (
	"context"

	coreprovider "github.com/agile-crypto/citius-core/provider"
	storageprovider "github.com/agile-crypto/citius-server/internal/storage/provider"
	"github.com/agile-crypto/citius-server/vault-storage/vaultlogical"
	"github.com/hashicorp/vault/sdk/logical"
)

// VaultRepository is the provider-instance repository built by
// NewVaultRepository.
type VaultRepository = storageprovider.StorageRepository

// NewVaultRepository returns a provider-instance repository backed by the
// given Vault storage.
func NewVaultRepository(ctx context.Context, s logical.Storage, opt ...coreprovider.Option) (*VaultRepository, error) {
	return storageprovider.NewStorageRepository(ctx, vaultlogical.FromLogical(s), opt...)
}
