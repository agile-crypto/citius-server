package key

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/logical"
	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/errors"
	"google.golang.org/protobuf/proto"
)

type VaultRepository struct {
	mu          *sync.RWMutex
	keys        logical.Storage // Storage view for keys (prefix: "key/")
	keyVersions logical.Storage // Storage view for key versions (prefix: "key_version/")
}

const keyStoragePrefix = "key/"
const keyVersionStoragePrefix = "key_version/"
const versionSep = ":"

var _ Repository = (*VaultRepository)(nil)

func NewVaultRepository(ctx context.Context, storage logical.Storage, opt ...Option) (*VaultRepository, error) {
	const op errors.Op = "key.NewVaultRepository"
	if storage == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "nil storage")
	}
	keys := logical.NewStorageView(storage, keyStoragePrefix)
	keyVersions := logical.NewStorageView(storage, keyVersionStoragePrefix)
	return &VaultRepository{
		mu:          &sync.RWMutex{},
		keys:        keys,
		keyVersions: keyVersions,
	}, nil
}

func put(ctx context.Context, view logical.Storage, key string, value proto.Message) error {
	const op errors.Op = "key.put"
	b, err := proto.Marshal(value)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	entry := &logical.StorageEntry{
		Key:   key,
		Value: b,
	}

	if err := view.Put(ctx, entry); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func get(ctx context.Context, view logical.Storage, key string, result proto.Message) error {
	const op errors.Op = "key.get"

	entry, err := view.Get(ctx, key)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return errors.New(ctx, op, errors.CodeKeyNotFound, "key not found: "+key)
	}

	if err := proto.Unmarshal(entry.Value, result); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *VaultRepository) getKey(ctx context.Context, key string) (*Key, error) {
	const op errors.Op = "key.(VaultRepository).getKey"
	// Store objects are persisted in memory
	storedKey := &storepb.StoredKey{}
	if err := get(ctx, r.keys, key, storedKey); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return NewKey(storedKey), nil
}

func (r *VaultRepository) getKeyVersion(ctx context.Context, key string, version uint32) (*KeyVersion, error) {
	const op errors.Op = "key.(VaultRepository).getKeyVersion"
	storedVersion := &storepb.StoredKeyVersion{}
	if err := get(ctx, r.keyVersions, versionKey(key, version), storedVersion); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return NewVersion(storedVersion), nil
}

func (r *VaultRepository) putKey(ctx context.Context, key string, value *Key) error {
	return put(ctx, r.keys, key, value.stored)
}

func versionKey(keyId string, version uint32) string {
	return versionKeyStr(keyId, fmt.Sprintf("%d", version))
}

func versionKeyStr(keyId, version string) string {
	return strings.Join([]string{keyId, version}, versionSep)
}

func versionPrefix(keyId string) string {
	return keyId + versionSep
}

func (r *VaultRepository) putKeyVersion(ctx context.Context, key string, value *KeyVersion) error {
	versionKey := versionKey(key, value.VersionNumber())
	return put(ctx, r.keyVersions, versionKey, value.stored)
}

func (r *VaultRepository) CreateKey(ctx context.Context, k *Key, initialVersion *KeyVersion) error {
	const op errors.Op = "key.(VaultRepository).CreateKey"
	if k == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "key must not be nil")
	}
	if initialVersion == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "initialVersion must not be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	keyId := k.PublicID()
	k0, err := r.getKey(ctx, keyId)
	if err != nil && !errors.IsKeyNotFound(err) {
		return errors.Wrap(ctx, op, err)
	}
	if k0 != nil {
		return errors.New(ctx, op, errors.CodeAlreadyExists, "key already exists: "+keyId)
	}

	// Assign version 1 to the initial version.
	initialVersion.StoredKeyVersion().VersionNumber = 1
	initialVersion.StoredKeyVersion().IsCurrent = true

	// Store the key and its first version atomically.
	// stored := k.Clone() // No need to clone; marshalled
	k.StoredKey().CurrentVersion = 1
	if err := r.putKey(ctx, keyId, k); err != nil {
		return errors.Wrap(ctx, op, err)
	}

	if err := r.putKeyVersion(ctx, keyId, initialVersion); err != nil {
		return errors.Wrap(ctx, op, err)
	}

	return nil
}

// ── Key metadata reads ──

func (r *VaultRepository) GetKey(ctx context.Context, publicID string) (*Key, error) {
	const op errors.Op = "key.(VaultRepository).GetKey"
	r.mu.RLock()
	defer r.mu.RUnlock()

	k, err := r.getKey(ctx, publicID)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if k == nil {
		return nil, errors.New(ctx, op, errors.CodeKeyNotFound,
			"key not found: "+publicID)
	}
	return k, nil
}

func (r *VaultRepository) ListKeys(ctx context.Context) ([]*Key, error) {
	const op errors.Op = "key.(VaultRepository).ListKeys"
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids, err := r.keys.List(ctx, "")
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	out := make([]*Key, 0, len(ids))
	for _, id := range ids {
		k, err := r.getKey(ctx, id)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		out = append(out, k)
	}
	return out, nil
}

// ── Key metadata updates ──

func (r *VaultRepository) UpdateKey(ctx context.Context, k *Key) error {
	//TODO: Validation needed to prevent invalid state? For example, disallow updating current_version to a non-existent version number?
	// Or should that be the orchestrator's responsibility?
	const op errors.Op = "key.(VaultRepository).UpdateKey"
	if k == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "key must not be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	keyId := k.PublicID()
	current, err := r.getKey(ctx, keyId)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if current == nil {
		return errors.New(ctx, op, errors.CodeKeyNotFound,
			"key not found: "+keyId)
	}
	if err := r.putKey(ctx, keyId, k); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// ── Aggregate deletion (cascading) ──

func (r *VaultRepository) DeleteKey(ctx context.Context, publicID string) error {
	const op errors.Op = "key.(VaultRepository).DeleteKey"
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

	if err := r.keys.Delete(ctx, publicID); err != nil {
		return errors.Wrap(ctx, op, err)
	}

	versions, err := r.keyVersions.List(ctx, versionPrefix(publicID))
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	for _, v := range versions {
		if err := r.keyVersions.Delete(ctx, versionKeyStr(publicID, v)); err != nil {
			return errors.Wrap(ctx, op, err)
		}
	}
	return nil
}

// ── Version operations ──

func (r *VaultRepository) AddVersion(ctx context.Context, keyName string, version *KeyVersion) error {
	const op errors.Op = "key.(VaultRepository).AddVersion"
	if version == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"version must not be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Look up the parent key to get current_version.
	k, err := r.getKey(ctx, keyName)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if k == nil {
		return errors.New(ctx, op, errors.CodeKeyNotFound,
			"key not found: "+keyName)
	}

	oldVersion := k.StoredKey().GetCurrentVersion()
	oldKeyVersion, err := r.getKeyVersion(ctx, keyName, oldVersion)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if oldKeyVersion == nil {
		return errors.New(ctx, op, errors.CodeKeyNotFound,
			"current version not found for key: "+keyName)
	}

	// Update new key version
	newVersion := oldVersion + 1
	version.StoredKeyVersion().VersionNumber = newVersion
	version.StoredKeyVersion().IsCurrent = true
	// update old key version
	oldKeyVersion.stored.IsCurrent = false
	// update key metadata
	k.StoredKey().CurrentVersion = newVersion

	// Store all versions
	if err := r.putKeyVersion(ctx, keyName, version); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if err := r.putKeyVersion(ctx, keyName, oldKeyVersion); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if err := r.putKey(ctx, keyName, k); err != nil {
		return errors.Wrap(ctx, op, err)
	}

	return nil
}

func (r *VaultRepository) GetVersion(ctx context.Context, keyName string, versionNumber uint32) (*KeyVersion, error) {
	const op errors.Op = "key.(VaultRepository).GetVersion"
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, err := r.getKeyVersion(ctx, keyName, versionNumber)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if v == nil {
		return nil, errors.New(ctx, op, errors.CodeKeyNotFound,
			"version not found for key: "+keyName)
	}
	return v, nil
}
