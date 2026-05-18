package key

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/logical"
	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type VaultRepository struct {
	mu          *sync.RWMutex
	keys        logical.Storage // Storage view for keys (prefix: "key/")
	keyVersions logical.Storage // Storage view for key versions (prefix: "key_version/")

	keyNameToID      logical.Storage       // storage view for name to id mapping (prefix: "key_name_to_id/")
	keyNameToIDCache cache[string, string] // cache for name to id mapping
	// optional override function to resolve key name to public ID. Defaults to nil, in which case a dedicated storage is used.
	keyNameToIDFunc func(name string) (string, error)
}

const keyStoragePrefix string = "key/"
const keyVersionStoragePrefix string = "key_version/"
const keyNameToIDStoragePrefix string = "key_name_to_id/"
const versionSep string = ":"

var _ Repository = (*VaultRepository)(nil)

// Key repositories can share the same lock, provided as option. This allows to create per-request
// repositories that share the same lock, so that they can be used concurrently.
// By default, a single instance of VaultRepository is thread-safe (has its own lock).
//
// Available options:
//   - withLock (optional): defaults to a new RWMutex. Supply a shared lock to coordinate with other repositories.
//   - withKeyNameToIDFunc (optional): overwrites the default name to id mapping behavior.
//     By default, the repository stores a mapping from key name to public ID in vault, and uses that for name-based lookups.
//     If this function is provided, it is used to resolve key names to IDs instead, and the repository does not store the mapping in vault.
//     This can be used to integrate with an external system of record for key name to ID mapping, for example.
//   - withKeyNameToIDCacheSize (optional): cache size for name to id mapping; only used if withKeyNameToIDFunc is nil.
//   - withCacheFactoryFunc (optional): factory function for creating the name to id cache. Defaults to an in-memory LRU
//     cache. Only used if withKeyNameToIDFunc is nil.
//
// Note about name to id mapping storage and caching:
//   - Mapping is cached when it is stored for the first time.
//   - Mapping is never updated (both in storage and cache) after creation as name updates are not allowed.
//   - Mapping is deleted from cache and storage when key is deleted.
//   - Mapping is cached only upon mapping storage lookup (ie. when a name is resolved to an ID). No caching happens when the storage is
//     not hit (ie. when key fetched by ID).
func NewVaultRepository(ctx context.Context, storage logical.Storage, opt ...Option) (*VaultRepository, error) {
	const op errors.Op = "key.NewVaultRepository"
	if storage == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "nil storage")
	}
	keys := logical.NewStorageView(storage, keyStoragePrefix)
	keyVersions := logical.NewStorageView(storage, keyVersionStoragePrefix)
	opts := getOpts(opt...)

	if opts.withKeyNameToIDFunc != nil {
		return &VaultRepository{
			mu:               opts.withLock,
			keys:             keys,
			keyVersions:      keyVersions,
			keyNameToIDFunc:  opts.withKeyNameToIDFunc,
			keyNameToID:      nil,
			keyNameToIDCache: nil,
		}, nil
	}

	cache := opts.withCacheFactoryFunc(opts.withKeyNameToIDCacheSize)
	keyNameToIDStorage := logical.NewStorageView(storage, keyNameToIDStoragePrefix)
	return &VaultRepository{
		mu:               opts.withLock,
		keys:             keys,
		keyVersions:      keyVersions,
		keyNameToIDFunc:  nil,
		keyNameToID:      keyNameToIDStorage,
		keyNameToIDCache: cache,
	}, nil

}

// storeKeyNameToID stores the mapping from key name to public ID in storage, if a custom name to id function is not provided.
// If a custom function is provided, this is a no-op, as we assume the function can resolve the mapping.
// Caches the mapping if no custom function is provided. Caller should handle cache invalidation if needed.
func (r *VaultRepository) storeKeyNameToID(ctx context.Context, name, id string) error {
	const op errors.Op = "key.(VaultRepository).storeKeyNameToID"
	if r.keyNameToIDFunc != nil {
		// if a custom name to id function is provided, we do not store the mapping in vault, as we assume the function can resolve it.
		return nil
	}
	if name == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "name must not be empty")
	}
	if id == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "id must not be empty")
	}
	v, err := r.keyNameToID.Get(ctx, name)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if v != nil {
		return errors.New(ctx, op, errors.CodeAlreadyExists, "key name already exists: "+name)
	}
	entry := &logical.StorageEntry{
		Key:   name,
		Value: []byte(id),
	}
	if err := r.keyNameToID.Put(ctx, entry); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	r.keyNameToIDCache.put(name, id)
	return nil
}

func (r *VaultRepository) deleteKeyNameToID(ctx context.Context, name string) error {
	const op errors.Op = "key.(VaultRepository).deleteKeyNameToID"
	if r.keyNameToIDFunc != nil {
		// if a custom name to id function is provided, we do not store the mapping in vault, so no need to delete.
		return nil
	}
	if name == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "name must not be empty")
	}
	// invalidate cache
	r.keyNameToIDCache.remove(name)
	if err := r.keyNameToID.Delete(ctx, name); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// resolveKeyNameToId resolves the key name to public ID, using the custom function if provided, or looking up in storage if not.
// Uses the cache for storage lookups. Caches the result of storage lookups, in case of cache misses.
// Caller should handle cache invalidation if needed.
func (r *VaultRepository) resolveKeyNameToID(ctx context.Context, name string) (string, error) {
	const op errors.Op = "key.(VaultRepository).resolveKeyNameToID"
	if r.keyNameToIDFunc != nil {
		// if a custom name to id function is provided, use it to resolve the name to id.
		return r.keyNameToIDFunc(name)
	}
	if name == "" {
		return "", errors.New(ctx, op, errors.CodeInvalidArgument, "name must not be empty")
	}
	if id, ok := r.keyNameToIDCache.get(name); ok {
		return id, nil
	}
	// if cache miss, look up in storage
	entry, err := r.keyNameToID.Get(ctx, name)
	if err != nil {
		return "", errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return "", errors.New(ctx, op, errors.CodeKeyNotFound, "key name not found: "+name)
	}
	id := string(entry.Value)
	r.keyNameToIDCache.put(name, id)
	return id, nil
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

func (r *VaultRepository) getKey(ctx context.Context, id string) (*Key, error) {
	const op errors.Op = "key.(VaultRepository).getKey"
	// Store objects are persisted in memory
	storedKey := &storepb.Key{}
	err := get(ctx, r.keys, id, storedKey)
	if err != nil {
		if errors.IsKeyNotFound(err) {
			return nil, errors.New(ctx, op, errors.CodeKeyNotFound, "Key not found: "+id)
		} else {
			return nil, errors.Wrap(ctx, op, err)
		}
	}
	return NewKey(storedKey), nil
}

func (r *VaultRepository) getKeyVersion(ctx context.Context, keyID string, version uint32) (*Version, error) {
	const op errors.Op = "key.(VaultRepository).getKeyVersion"
	storedVersion := &storepb.KeyVersion{}
	err := get(ctx, r.keyVersions, versionKey(keyID, version), storedVersion)
	if err != nil {
		if errors.IsKeyNotFound(err) {
			return nil, errors.New(ctx, op, errors.CodeKeyNotFound,
				fmt.Sprintf("Key version not found (keyId=%s,version=%d)", keyID, version))
		}
		return nil, errors.Wrap(ctx, op, err)
	}
	return NewVersion(storedVersion), nil
}

// Set create and update time.
// Handles storing name to id mapping.
// Returns CodeAlreadyExists if a key with the same PublicID already exists.
func (r *VaultRepository) putKey(ctx context.Context, value *Key, vetForWrite bool) error {
	const op = "key.(VaultRepository).putKey"
	if vetForWrite {
		if err := value.VetForWrite(ctx, core.OpCreate); err != nil {
			return errors.Wrap(ctx, op, err)
		}
	}
	old, err := r.getKey(ctx, value.PublicId)
	if err != nil && !errors.IsKeyNotFound(err) {
		return errors.Wrap(ctx, op, err)
	}
	if old != nil {
		return errors.New(ctx, op, errors.CodeAlreadyExists, "key already exists: "+value.PublicId)
	}
	now := timestamppb.Now()
	value.CreateTime = now
	value.UpdateTime = now

	if err := r.storeKeyNameToID(ctx, value.Name, value.PublicId); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if err := put(ctx, r.keys, value.PublicId, value.Key); err != nil {
		_ = r.deleteKeyNameToID(ctx, value.Name) // best effort cleanup
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// Set update time but not create time.
// Returns CodeKeyNotFound if the key does not already exist.
// Returns CodeInvalidArgument if the key name is being updated to a different value, as name updates are not allowed.
func (r *VaultRepository) updateKey(ctx context.Context, value *Key, vetForWrite bool) error {
	const op = "key.(VaultRepository).updateKey"
	if vetForWrite {
		if err := value.VetForWrite(ctx, core.OpUpdate); err != nil {
			return errors.Wrap(ctx, op, err)
		}
	}
	old, err := r.getKey(ctx, value.PublicId)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if old == nil {
		return errors.New(ctx, op, errors.CodeKeyNotFound, "key not found: "+value.PublicId)
	}
	if old.Name != value.Name {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "key name cannot be updated")
	}
	value.UpdateTime = timestamppb.Now()
	if err := put(ctx, r.keys, value.PublicId, value.Key); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// Handles deleting the key name to id mapping, as well as the key itself. Returns nil if the key is not found.
func (r *VaultRepository) deleteKey(ctx context.Context, id string) error {
	key, err := r.getKey(ctx, id)
	if err != nil {
		return errors.Wrap(ctx, "key.(VaultRepository).deleteKey", err)
	}
	// delete name to id mapping
	if err := r.deleteKeyNameToID(ctx, key.Name); err != nil {
		return errors.Wrap(ctx, "key.(VaultRepository).deleteKey", err)
	}

	return r.keys.Delete(ctx, id)
}

func versionKey(keyID string, version uint32) string {
	return versionKeyStr(keyID, fmt.Sprintf("%d", version))
}

func versionKeyStr(keyID, version string) string {
	return strings.Join([]string{keyID, version}, versionSep)
}

func versionPrefix(keyID string) string {
	return keyID + versionSep
}

// set create and update time
// fails if version already exists
func (r *VaultRepository) putKeyVersion(ctx context.Context, value *Version, vetForWrite bool) error {
	const op = "key.(VaultRepository).putKeyVersion"
	if vetForWrite {
		if err := value.VetForWrite(ctx, core.OpCreate); err != nil {
			return errors.Wrap(ctx, op, err)
		}
	}
	old, err := r.getKeyVersion(ctx, value.KeyId, value.Version)
	if err != nil && !errors.IsKeyNotFound(err) {
		return errors.Wrap(ctx, op, err)
	}
	if old != nil {
		return errors.New(ctx, op, errors.CodeAlreadyExists, "key version already exists: (keyId: "+value.KeyId+", version: "+fmt.Sprintf("%d", value.Version)+")")
	}
	now := timestamppb.Now()
	value.CreateTime = now
	value.UpdateTime = now
	return put(ctx, r.keyVersions, versionKey(value.KeyId, value.Version), value.KeyVersion)
}

func (r *VaultRepository) CreateKey(ctx context.Context, key *Key, initialVersion *Version, opt ...Option) error {
	const op errors.Op = "key.(VaultRepository).CreateKey"
	if key == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "key must not be nil")
	}
	if initialVersion == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "initialVersion must not be nil")
	}
	if key.PublicId != initialVersion.KeyId {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "key PublicId and initialVersion KeyId must match")
	}
	opts := getOpts(opt...)
	if initialVersion.Version != opts.withInitialVersion {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("invalid initial version number (expected: %d, got: %d)", opts.withInitialVersion, initialVersion.Version))
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.putKey(ctx, key, opts.withVetForWrite); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if err := r.putKeyVersion(ctx, initialVersion, opts.withVetForWrite); err != nil {
		_ = r.deleteKey(ctx, key.PublicId) // best effort cleanup
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// ── Key metadata reads ──

func (r *VaultRepository) GetKeyByID(ctx context.Context, publicID string) (*Key, error) {
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
	return k.Clone(), nil
}

func (r *VaultRepository) GetKeyByName(ctx context.Context, name string) (*Key, error) {
	const op errors.Op = "key.(VaultRepository).GetKeyByName"
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, err := r.resolveKeyNameToID(ctx, name)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return r.GetKeyByID(ctx, id)
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
		out = append(out, k.Clone())
	}
	return out, nil
}

// ── Key metadata updates ──

func (r *VaultRepository) UpdateKey(ctx context.Context, k *Key, opt ...Option) error {
	//TODO: Validation needed to prevent invalid state? For example, disallow updating current_version to a non-existent version number?
	// Or should that be the orchestrator's responsibility?
	const op errors.Op = "key.(VaultRepository).UpdateKey"
	if k == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "key must not be nil")
	}
	opts := getOpts(opt...)

	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.updateKey(ctx, k, opts.withVetForWrite); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// ── Aggregate deletion (cascading) ──

func (r *VaultRepository) DeleteKey(ctx context.Context, id string) error {
	const op errors.Op = "key.(VaultRepository).DeleteKey"
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.deleteKey(ctx, id); err != nil {
		return errors.Wrap(ctx, op, err)
	}

	versions, err := r.keyVersions.List(ctx, versionPrefix(id))
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	for _, v := range versions {
		if err := r.keyVersions.Delete(ctx, versionKeyStr(id, v)); err != nil {
			return errors.Wrap(ctx, op, err)
		}
	}
	return nil
}

// ── Version operations ──

// fails if the version number does not match the current version + 1, or if the parent key does not exist
func (r *VaultRepository) AddVersion(ctx context.Context, version *Version, opt ...Option) error {
	const op errors.Op = "key.(VaultRepository).AddVersion"
	if version.KeyId == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"keyId is required")
	}
	opts := getOpts(opt...)

	r.mu.Lock()
	defer r.mu.Unlock()

	k, err := r.getKey(ctx, version.KeyId)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if version.Version != k.CurrentVersion+1 {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("invalid next version number (expected: %d, got: %d)", k.CurrentVersion+1, version.Version))
	}

	newKey := k.Clone()
	newKey.CurrentVersion += 1

	err = r.putKeyVersion(ctx, version, opts.withVetForWrite)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	err = r.updateKey(ctx, newKey, opts.withVetForWrite)
	if err != nil {
		_ = r.keyVersions.Delete(ctx, versionKey(version.KeyId, version.Version)) // best-effort cleanup
		return errors.Wrap(ctx, op, err)
	}

	return nil
}

func (r *VaultRepository) getCurrentVersionInternal(ctx context.Context, keyID string) (*Version, error) {
	const op errors.Op = "key.(VaultRepository).getCurrentVersionInternal"
	k, err := r.getKey(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	v, err := r.getKeyVersion(ctx, keyID, k.CurrentVersion)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return v, nil
}

func (r *VaultRepository) GetCurrentVersion(ctx context.Context, keyID string) (*Version, error) {
	const op errors.Op = "key.(VaultRepository).GetCurrentVersion"
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, err := r.getCurrentVersionInternal(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return v, nil

}

func (r *VaultRepository) getVersionInternal(ctx context.Context, keyID string, versionNumber uint32) (*Version, error) {
	const op errors.Op = "key.(VaultRepository).getVersionInternal"

	v, err := r.getKeyVersion(ctx, keyID, versionNumber)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return v, nil
}
func (r *VaultRepository) GetVersion(ctx context.Context, keyID string, versionNumber uint32) (*Version, error) {
	const op errors.Op = "key.(VaultRepository).GetVersion"
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, err := r.getVersionInternal(ctx, keyID, versionNumber)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return v, nil
}
