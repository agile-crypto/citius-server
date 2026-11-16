// Package policy builds the policy repository over a Vault logical.Storage.
//
// The repository itself lives in internal/storage/policy and depends only on
// storage.Storage; this package adapts the Vault storage and delegates.
package policy

import (
	"context"

	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-server/vault-storage/vaultlogical"
	"github.com/hashicorp/vault/sdk/logical"
)

// VaultRepository is the policy repository built by NewVaultRepository.
type VaultRepository = policy.StorageRepository

// NewVaultRepository returns a policy repository backed by the given Vault
// storage.
func NewVaultRepository(ctx context.Context, s logical.Storage, opt ...policy.Option) (*VaultRepository, error) {
	return policy.NewStorageRepository(ctx, vaultlogical.FromLogical(s), opt...)
}
