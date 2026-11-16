// Package vaultlogical adapts Vault's logical.Storage to storage.Storage.
//
// It is the only place where the storage repositories meet the Vault SDK:
// the constructors in this module wrap a logical.Storage (typically
// req.Storage) with FromLogical before building a repository over it.
package vaultlogical

import (
	"context"

	"github.com/agile-crypto/citius-core/storage"
	"github.com/hashicorp/vault/sdk/logical"
)

// Adapter exposes a logical.Storage as a storage.Storage.
type Adapter struct {
	s logical.Storage
}

var _ storage.Storage = (*Adapter)(nil)

// FromLogical wraps s. It returns nil when s is nil, so the repositories'
// nil-storage checks still apply.
func FromLogical(s logical.Storage) storage.Storage {
	if s == nil {
		return nil
	}
	return &Adapter{s: s}
}

// Unwrap returns the underlying logical.Storage.
func (a *Adapter) Unwrap() logical.Storage { return a.s }

// List implements storage.Storage.
func (a *Adapter) List(ctx context.Context, prefix string) ([]string, error) {
	return a.s.List(ctx, prefix)
}

// Get implements storage.Storage.
func (a *Adapter) Get(ctx context.Context, key string) (*storage.Entry, error) {
	e, err := a.s.Get(ctx, key)
	if err != nil || e == nil {
		return nil, err
	}
	return &storage.Entry{Key: e.Key, Value: e.Value, SealWrap: e.SealWrap}, nil
}

// Put implements storage.Storage.
func (a *Adapter) Put(ctx context.Context, entry *storage.Entry) error {
	if entry == nil {
		return a.s.Put(ctx, nil)
	}
	return a.s.Put(ctx, &logical.StorageEntry{Key: entry.Key, Value: entry.Value, SealWrap: entry.SealWrap})
}

// Delete implements storage.Storage.
func (a *Adapter) Delete(ctx context.Context, key string) error {
	return a.s.Delete(ctx, key)
}
