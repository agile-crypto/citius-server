package key

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/logical"
	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/storage"
	"google.golang.org/protobuf/proto"
)

type VaultRepository struct {
	storage storage.Storage
	// keys        logical.Storage // Storage view for keys (prefix: "key/")
	// keyVersions logical.Storage // Storage view for key versions (prefix: "key_version/")
}

const keyStoragePrefix = "key/"
const keyVersionStoragePrefix = "key_version/"
const versionSep = ":"

var _ Repository = (*VaultRepository)(nil)

func NewVaultRepository(ctx context.Context, storage logical.Storage) (*VaultRepository, error) {
	const op errors.Op = "key.NewVaultRepository"
	if storage == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "nil storage")
	}
	return &VaultRepository{
		storage: storage,
	}, nil
}

func put(ctx context.Context, s storage.Storage, key string, value proto.Message) error {
	const op errors.Op = "key.put"
	b, err := json.Marshal(value)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	entry := &logical.StorageEntry{
		Key:   key,
		Value: b,
	}

	if err := s.Put(ctx, entry); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func get(ctx context.Context, s storage.Storage, key string, result proto.Message) error {
	const op errors.Op = "key.get"

	entry, err := s.Get(ctx, key)
	if err != nil {
		return result, errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return result, errors.New(ctx, op, errors.CodeKeyNotFound, "key not found: "+key)
	}

	if err := json.Unmarshal(entry.Value, &result); err != nil {
		return result, errors.Wrap(ctx, op, err)
	}
	return result, nil
}

func getKey(ctx context.Context, s storage.Storage, key string) (*Key, error) {
	const op errors.Op = "key.(VaultRepository).getKey"
	// Store objects are persisted in memory
	storedKey := &storepb.StoredKey{}
	if err := get(ctx, s, keyStoragePrefix+key, storedKey); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return NewKey(storedKey), nil
}

func getKeyVersion(ctx context.Context, s storage.Storage, key string, version uint32) (*KeyVersion, error) {
	const op errors.Op = "key.(VaultRepository).getKeyVersion"
	storedVersion := &storepb.StoredKeyVersion{}
	if err := get(ctx, s, keyVersionStoragePrefix+versionKey(key, version), storedVersion); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return NewVersion(storedVersion), nil
}

func putKey(ctx context.Context, s storage.Storage, key string, value *Key, opType core.WriteOp) error {
	const op errors.Op = "key.(VaultRepository).putKey"
	if err := value.VetForWrite(ctx, opType); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return put(ctx, s, keyStoragePrefix+key, value.stored)
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

func putKeyVersion(ctx context.Context, s storage.Storage, key string, value *KeyVersion, opType core.WriteOp) error {
	const op errors.Op = "key.(VaultRepository).putKeyVersion"
	if err := value.VetForWrite(ctx, opType); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	versionKey := versionKey(key, value.VersionNumber())
	return put(ctx, s, keyVersionStoragePrefix+versionKey, value.stored)
}

func (r *VaultRepository) CreateKey(ctx context.Context, k *Key, initialVersion *KeyVersion) error {
	const op errors.Op = "key.(VaultRepository).CreateKey"
	if k == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "key must not be nil")
	}
	if initialVersion == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "initialVersion must not be nil")
	}

	txHandler := func(s storage.Storage) error {
		keyId := k.PublicID()
		k0, err := getKey(ctx, s, keyId)
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
		if err := putKey(ctx, s, keyId, k, core.OpCreate); err != nil {
			return errors.Wrap(ctx, op, err)
		}

		if err := putKeyVersion(ctx, s, keyId, initialVersion, core.OpCreate); err != nil {
			return errors.Wrap(ctx, op, err)
		}

		return nil
	}

	if err := r.storage.DoTx(ctx, txHandler); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// ── Key metadata reads ──

func (r *VaultRepository) GetKey(ctx context.Context, publicID string) (*Key, error) {
	const op errors.Op = "key.(VaultRepository).GetKey"

	k, err := getKey(ctx, r.storage, publicID)
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

	// TODO: Txn required?
	ids, err := r.storage.List(ctx, keyStoragePrefix)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	out := make([]*Key, 0, len(ids))
	for _, id := range ids {
		k, err := getKey(ctx, r.storage, id)
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

	txHandler := func(s storage.Storage) error {
		keyId := k.PublicID()
		current, err := getKey(ctx, r.storage, keyId)
		if err != nil {
			return errors.Wrap(ctx, op, err)
		}
		if current == nil {
			return errors.New(ctx, op, errors.CodeKeyNotFound,
				"key not found: "+keyId)
		}
		if err := putKey(ctx, r.storage, keyId, k, core.OpUpdate); err != nil {
			return errors.Wrap(ctx, op, err)
		}
		return nil
	}

	if err := r.storage.DoTx(ctx, txHandler); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// ── Aggregate deletion (cascading) ──

func (r *VaultRepository) DeleteKey(ctx context.Context, publicID string) error {
	const op errors.Op = "key.(VaultRepository).DeleteKey"

	txHandler := func(s storage.Storage) error {
		k, err := getKey(ctx, s, publicID)
		if err != nil {
			return errors.Wrap(ctx, op, err)
		}
		if k == nil {
			return errors.New(ctx, op, errors.CodeKeyNotFound,
				"key not found: "+publicID)
		}

		if err := s.Delete(ctx, keyStoragePrefix+publicID); err != nil {
			return errors.Wrap(ctx, op, err)
		}

		versions, err := s.List(ctx, keyVersionStoragePrefix+versionPrefix(publicID))
		if err != nil {
			return errors.Wrap(ctx, op, err)
		}
		for _, v := range versions {
			if err := s.Delete(ctx, keyVersionStoragePrefix+versionKeyStr(publicID, v)); err != nil {
				return errors.Wrap(ctx, op, err)
			}
		}
		return nil
	}

	if err := r.storage.DoTx(ctx, txHandler); err != nil {
		return errors.Wrap(ctx, op, err)
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

	txHandler := func(s storage.Storage) error {
		k, err := getKey(ctx, s, keyName)
		if err != nil {
			return errors.Wrap(ctx, op, err)
		}
		if k == nil {
			return errors.New(ctx, op, errors.CodeKeyNotFound,
				"key not found: "+keyName)
		}

		oldVersion := k.StoredKey().GetCurrentVersion()
		oldKeyVersion, err := getKeyVersion(ctx, s, keyName, oldVersion)
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
		if err := putKeyVersion(ctx, s, keyName, version, core.OpCreate); err != nil {
			return errors.Wrap(ctx, op, err)
		}
		if err := putKeyVersion(ctx, s, keyName, oldKeyVersion, core.OpUpdate); err != nil {
			return errors.Wrap(ctx, op, err)
		}
		if err := putKey(ctx, s, keyName, k, core.OpUpdate); err != nil {
			return errors.Wrap(ctx, op, err)
		}
		return nil
	}

	if err := r.storage.DoTx(ctx, txHandler); err != nil {
		return errors.Wrap(ctx, op, err)
	}

	return nil
}

func (r *VaultRepository) GetVersion(ctx context.Context, keyName string, versionNumber uint32) (*KeyVersion, error) {
	const op errors.Op = "key.(VaultRepository).GetVersion"

	v, err := getKeyVersion(ctx, r.storage, keyName, versionNumber)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if v == nil {
		return nil, errors.New(ctx, op, errors.CodeKeyNotFound,
			"version not found for key: "+keyName)
	}
	return v, nil
}
