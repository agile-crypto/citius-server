// Package template builds the template registry over a Vault
// logical.Storage.
//
// The registry itself lives in internal/storage/template and depends only on
// storage.Storage; this package adapts the Vault storage and delegates.
package template

import (
	"context"

	"github.com/agile-crypto/citius-core/template"
	"github.com/agile-crypto/citius-server/vault-storage/vaultlogical"
	"github.com/hashicorp/vault/sdk/logical"
)

// VaultRegistry is the template registry built by NewVaultRegistry.
type VaultRegistry = template.VaultRegistry

// NewVaultRegistry returns a template registry backed by the given Vault
// storage.
func NewVaultRegistry(ctx context.Context, s logical.Storage, opt ...template.Option) (*VaultRegistry, error) {
	return template.NewVaultRegistry(ctx, vaultlogical.FromLogical(s), opt...)
}
