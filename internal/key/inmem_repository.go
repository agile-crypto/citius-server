package key

import (
	"context"
	"sync"

	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/storage"
)

type InMemRepository struct {
	mu          sync.RWMutex
	keys        storage.Storage[*Key]                   // guarded by mu
	keyVersions storage.Storage[map[uint32]*KeyVersion] // guarded by mu
}

var _ Repository = (*InMemRepository)(nil)

func NewInMemoryRepository(keys storage.Storage[*Key], keyVersions storage.Storage[map[uint32]*KeyVersion]) *InMemRepository {
	return &InMemRepository{
		keys:        keys,
		keyVersions: keyVersions,
	}
}

func (r *InMemRepository) CreateKey(ctx context.Context, k *Key, initialVersion *KeyVersion) error {
	const op errors.Op = "key.(InMemRepository).CreateKey"
	if k == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "key must not be nil")
	}
	if initialVersion == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "initialVersion must not be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	keyId := k.PublicID()
	k0, err := r.keys.Get(ctx, keyId)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if k0 != nil {
		return errors.New(ctx, op, errors.CodeAlreadyExists, "key already exists: "+keyId)
	}

	// Assign version 1 to the initial version.
	initialVersion.StoredKeyVersion().VersionNumber = 1
	initialVersion.StoredKeyVersion().IsCurrent = true

	// Store the key and its first version atomically.
	stored := k.Clone()
	stored.StoredKey().CurrentVersion = 1
	if err := r.keys.Put(ctx, keyId, stored); err != nil {
		return errors.Wrap(ctx, op, err)
	}

	// TODO: change identifier for keyVersions
	m := map[uint32]*KeyVersion{
		1: initialVersion.Clone(),
	}
	if err := r.keyVersions.Put(ctx, keyId, m); err != nil {
		return errors.Wrap(ctx, op, err)
	}

	return nil
}

// ── Key metadata reads ──

func (r *InMemRepository) GetKey(ctx context.Context, publicID string) (*Key, error) {
	const op errors.Op = "key.(InMemRepository).GetKey"
	r.mu.RLock()
	defer r.mu.RUnlock()

	k, err := r.keys.Get(ctx, publicID)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if k == nil {
		return nil, errors.New(ctx, op, errors.CodeKeyNotFound,
			"key not found: "+publicID)
	}
	return k.Clone(), nil
}

func (r *InMemRepository) ListKeys(ctx context.Context) ([]*Key, error) {
	const op errors.Op = "key.(InMemRepository).ListKeys"
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids, err := r.keys.List(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	out := make([]*Key, 0, len(ids))
	for _, id := range ids {
		k, err := r.keys.Get(ctx, id)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		out = append(out, k.Clone())
	}
	return out, nil
}

// ── Key metadata updates ──

func (r *InMemRepository) UpdateKey(ctx context.Context, k *Key) error {
	//TODO: Validation needed to prevent invalid state? For example, disallow updating current_version to a non-existent version number?
	// Or should that be the orchestrator's responsibility?
	const op errors.Op = "key.(InMemRepository).UpdateKey"
	if k == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "key must not be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	keyId := k.PublicID()
	current, err := r.keys.Get(ctx, keyId)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if current == nil {
		return errors.New(ctx, op, errors.CodeKeyNotFound,
			"key not found: "+keyId)
	}
	err = r.keys.Put(ctx, keyId, k.Clone())
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// ── Aggregate deletion (cascading) ──

func (r *InMemRepository) DeleteKey(ctx context.Context, publicID string) error {
	const op errors.Op = "key.(InMemRepository).DeleteKey"
	r.mu.Lock()
	defer r.mu.Unlock()

	k, err := r.keys.Get(ctx, publicID)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if k == nil {
		return errors.New(ctx, op, errors.CodeKeyNotFound,
			"key not found: "+publicID)
	}

	err = r.keys.Delete(ctx, publicID)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}

	err = r.keyVersions.Delete(ctx, publicID)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}

	return nil
}

// ── Version operations ──

func (r *InMemRepository) AddVersion(ctx context.Context, keyName string, version *KeyVersion) error {
	const op errors.Op = "key.(InMemRepository).AddVersion"
	if version == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"version must not be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Look up the parent key to get current_version.
	k, err := r.keys.Get(ctx, keyName)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if k == nil {
		return errors.New(ctx, op, errors.CodeKeyNotFound,
			"key not found: "+keyName)
	}

	oldVersion := k.StoredKey().GetCurrentVersion()
	versions, err := r.keyVersions.Get(ctx, keyName)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if versions == nil {
		return errors.New(ctx, op, errors.CodeKeyNotFound,
			"no versions found for key: "+keyName)
	}
	oldKeyVersion, exists := versions[oldVersion]
	if !exists {
		return errors.New(ctx, op, errors.CodeKeyNotFound,
			"current version not found for key: "+keyName)
	}

	// Mark the old version as not current.
	oldKeyVersion.StoredKeyVersion().IsCurrent = false

	newVersion := oldVersion + 1
	version.StoredKeyVersion().VersionNumber = newVersion
	version.StoredKeyVersion().IsCurrent = true

	versions[newVersion] = version.Clone()
	err = r.keyVersions.Put(ctx, keyName, versions)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}

	// Update the parent key's current_version.
	k.StoredKey().CurrentVersion = newVersion
	err = r.keys.Put(ctx, keyName, k.Clone())
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *InMemRepository) GetVersion(ctx context.Context, keyName string, versionNumber uint32) (*KeyVersion, error) {
	const op errors.Op = "key.(InMemRepository).GetVersion"
	r.mu.RLock()
	defer r.mu.RUnlock()

	versions, err := r.keyVersions.Get(ctx, keyName)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	v, ok := versions[versionNumber]
	if !ok {
		return nil, errors.New(ctx, op, errors.CodeKeyNotFound,
			"version not found")
	}
	return v.Clone(), nil
}
