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
}

const keyStoragePrefix string = "key/"
const keyVersionStoragePrefix string = "key_version/"
const versionSep string = ":"

var _ Repository = (*VaultRepository)(nil)

// Key repositories can share the same lock, provided as option. This allows to create per-request
// repositories that share the same lock, so that they can be used concurrently.
// By default, a single instance of VaultRepository is thread-safe (has its own lock).
func NewVaultRepository(ctx context.Context, storage logical.Storage, opt ...Option) (*VaultRepository, error) {
	const op errors.Op = "key.NewVaultRepository"
	if storage == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "nil storage")
	}
	keys := logical.NewStorageView(storage, keyStoragePrefix)
	keyVersions := logical.NewStorageView(storage, keyVersionStoragePrefix)
	opts := getOpts(opt...)

	return &VaultRepository{
		mu:          opts.withLock,
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

func (r *VaultRepository) getKeyVersion(ctx context.Context, keyId string, version uint32) (*KeyVersion, error) {
	const op errors.Op = "key.(VaultRepository).getKeyVersion"
	storedVersion := &storepb.KeyVersion{}
	err := get(ctx, r.keyVersions, versionKey(keyId, version), storedVersion)
	if err != nil {
		if errors.IsKeyNotFound(err) {
			return nil, errors.New(ctx, op, errors.CodeKeyNotFound,
				fmt.Sprintf("Key version not found (keyId=%s,version=%d)", keyId, version))
		}
		return nil, errors.Wrap(ctx, op, err)
	}
	return NewKeyVersion(storedVersion), nil
}

// set create and update time
// fails if key already exists
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
	return put(ctx, r.keys, value.PublicId, value.Key)
}

// set update time but not create time
// fails if key dos not already exist
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
	value.UpdateTime = timestamppb.Now()
	return put(ctx, r.keys, value.PublicId, value.Key)
}

func (r *VaultRepository) deleteKey(ctx context.Context, id string) error {
	return r.keys.Delete(ctx, id)
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

// set create and update time
// fails if version already exists
func (r *VaultRepository) putKeyVersion(ctx context.Context, value *KeyVersion, vetForWrite bool) error {
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

// set update time but not create time
// fails if version does not already exist
func (r *VaultRepository) updateKeyVersion(ctx context.Context, value *KeyVersion, vetForWrite bool) error {
	const op = "key.(VaultRepository).updateKeyVersion"
	if vetForWrite {
		if err := value.VetForWrite(ctx, core.OpUpdate); err != nil {
			return errors.Wrap(ctx, op, err)
		}
	}
	old, err := r.getKeyVersion(ctx, value.KeyId, value.Version)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if old == nil {
		return errors.New(ctx, op, errors.CodeKeyNotFound, "key version not found: (keyId: "+value.KeyId+", version: "+fmt.Sprintf("%d", value.Version)+")")
	}
	value.UpdateTime = timestamppb.Now()
	return put(ctx, r.keyVersions, versionKey(value.KeyId, value.Version), value.KeyVersion)
}

func (r *VaultRepository) deleteKeyVersion(ctx context.Context, keyId string, version uint32) error {
	return r.keyVersions.Delete(ctx, versionKey(keyId, version))
}

func (r *VaultRepository) CreateKey(ctx context.Context, id string, templateId, providerId, policyId string,
	scopeSpec *core.ScopeSpec, keyMaterial []byte, opt ...Option) error {
	const op errors.Op = "key.(VaultRepository).CreateKey"
	opts := getOpts(opt...)
	if opts.withName == "" {
		// if no name is provided, default to id
		opts.withName = id
	}
	initialVersion := opts.withInitialVersion
	vid := versionKey(id, initialVersion)
	v, err := newKeyVersion(ctx, vid, id, templateId, providerId, initialVersion, keyMaterial, opt...)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	k, err := newKey(ctx, id, policyId, scopeSpec, initialVersion, opt...)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.putKey(ctx, k, opts.withVetForWrite); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if err := r.putKeyVersion(ctx, v, opts.withVetForWrite); err != nil {
		_ = r.deleteKey(ctx, id) // best effort cleanup
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
	return k.Clone(), nil
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

	k, err := r.keys.Get(ctx, id)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if k == nil {
		return errors.New(ctx, op, errors.CodeKeyNotFound,
			"key not found: "+id)
	}

	if err := r.keys.Delete(ctx, id); err != nil {
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
func (r *VaultRepository) AddVersion(ctx context.Context, keyId string, templateId, providerId string, keyMaterial []byte, opt ...Option) error {
	const op errors.Op = "key.(VaultRepository).AddVersion"
	if keyId == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"keyId is required")
	}
	opts := getOpts(opt...)

	r.mu.Lock()
	defer r.mu.Unlock()

	k, err := r.getKey(ctx, keyId)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	newVersionNumber := k.CurrentVersion + 1
	if opts.withPublicId == "" {
		opts.withPublicId = versionKey(keyId, newVersionNumber)
	}
	v, err := newKeyVersion(ctx, opts.withPublicId, keyId, templateId, providerId, newVersionNumber, keyMaterial, opt...)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	newKey := k.Clone()
	newKey.CurrentVersion = newVersionNumber

	err = r.putKeyVersion(ctx, v, opts.withVetForWrite)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	err = r.updateKey(ctx, newKey, opts.withVetForWrite)
	if err != nil {
		r.deleteKeyVersion(ctx, keyId, newVersionNumber)
		return errors.Wrap(ctx, op, err)
	}

	return nil
}

func (r *VaultRepository) getCurrentVersionInternal(ctx context.Context, keyId string) (*KeyVersion, error) {
	const op errors.Op = "key.(VaultRepository).getCurrentVersionInternal"
	k, err := r.getKey(ctx, keyId)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	v, err := r.getKeyVersion(ctx, keyId, k.CurrentVersion)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return v, nil
}

func (r *VaultRepository) GetCurrentVersion(ctx context.Context, keyId string) (*KeyVersion, error) {
	const op errors.Op = "key.(VaultRepository).GetCurrentVersion"
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, err := r.getCurrentVersionInternal(ctx, keyId)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return v, nil

}

func (r *VaultRepository) getVersionInternal(ctx context.Context, keyId string, versionNumber uint32) (*KeyVersion, error) {
	const op errors.Op = "key.(VaultRepository).getVersionInternal"

	v, err := r.getKeyVersion(ctx, keyId, versionNumber)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return v, nil
}
func (r *VaultRepository) GetVersion(ctx context.Context, keyId string, versionNumber uint32) (*KeyVersion, error) {
	const op errors.Op = "key.(VaultRepository).GetVersion"
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, err := r.getVersionInternal(ctx, keyId, versionNumber)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return v, nil
}
