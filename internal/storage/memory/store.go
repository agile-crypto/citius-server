package memory

import (
	"context"
	"sync"

	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/key"
)

const pkgName = "memory"

// MemoryStore is a goroutine-safe in-memory Storage implementation.
type MemoryStore struct {
	mu          sync.RWMutex
	keys        map[string]*key.Key
	keyVersions map[string]map[uint32]*key.KeyVersion // keyName → versionNumber → version
}

func New() *MemoryStore {
	return &MemoryStore{
		keys:        make(map[string]*key.Key),
		keyVersions: make(map[string]map[uint32]*key.KeyVersion),
	}
}

func (m *MemoryStore) CreateKey(_ context.Context, k *key.Key, initialVersion *key.KeyVersion) error {
	const op errors.Op = "memory.(MemoryStore).CreateKey"
	if k == nil {
		return errors.New(context.Background(), op, errors.CodeInvalidArgument, "key must not be nil")
	}
	if initialVersion == nil {
		return errors.New(context.Background(), op, errors.CodeInvalidArgument, "initialVersion must not be nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keys[k.PublicID()]; exists {
		return errors.New(context.Background(), op, errors.CodeAlreadyExists,
			"key already exists: "+k.PublicID())
	}

	// Assign version 1 to the initial version.
	initialVersion.StoredKeyVersion().VersionNumber = 1
	initialVersion.StoredKeyVersion().IsCurrent = true

	// Store the key and its first version atomically.
	stored := k.Clone()
	stored.StoredKey().CurrentVersion = 1
	m.keys[k.PublicID()] = stored

	m.keyVersions[k.PublicID()] = map[uint32]*key.KeyVersion{
		1: initialVersion.Clone(),
	}
	return nil
}

// ── Key metadata reads ──

func (m *MemoryStore) GetKey(_ context.Context, publicID string) (*key.Key, error) {
	const op errors.Op = "memory.(MemoryStore).GetKey"
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.keys[publicID]
	if !ok {
		return nil, errors.New(context.Background(), op, errors.CodeKeyNotFound,
			"key not found: "+publicID)
	}
	return k.Clone(), nil
}

func (m *MemoryStore) ListKeys(_ context.Context) ([]*key.Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*key.Key, 0, len(m.keys))
	for _, k := range m.keys {
		out = append(out, k.Clone())
	}
	return out, nil
}

// ── Key metadata updates ──

func (m *MemoryStore) UpdateKey(_ context.Context, k *key.Key) error {
	const op errors.Op = "memory.(MemoryStore).UpdateKey"
	if k == nil {
		return errors.New(context.Background(), op, errors.CodeInvalidArgument, "key must not be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[k.PublicID()]; !ok {
		return errors.New(context.Background(), op, errors.CodeKeyNotFound,
			"key not found: "+k.PublicID())
	}
	m.keys[k.PublicID()] = k.Clone()
	return nil
}

// ── Aggregate deletion (cascading) ──

func (m *MemoryStore) DeleteKey(_ context.Context, publicID string) error {
	const op errors.Op = "memory.(MemoryStore).DeleteKey"
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[publicID]; !ok {
		return errors.New(context.Background(), op, errors.CodeKeyNotFound,
			"key not found: "+publicID)
	}
	delete(m.keys, publicID)
	delete(m.keyVersions, publicID) // cascade
	return nil
}

// ── Version operations ──

func (m *MemoryStore) AddVersion(_ context.Context, keyName string, version *key.KeyVersion) error {
	const op errors.Op = "memory.(MemoryStore).AddVersion"
	if version == nil {
		return errors.New(context.Background(), op, errors.CodeInvalidArgument,
			"version must not be nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Look up the parent key to get current_version.
	k, ok := m.keys[keyName]
	if !ok {
		return errors.New(context.Background(), op, errors.CodeKeyNotFound,
			"key not found: "+keyName)
	}

	// Assign the next version number atomically.
	nextVer := k.StoredKey().GetCurrentVersion() + 1
	version.StoredKeyVersion().VersionNumber = nextVer
	version.StoredKeyVersion().IsCurrent = true

	// Clear is_current on the old current version (if any).
	if oldVer, exists := m.keyVersions[keyName][k.StoredKey().GetCurrentVersion()]; exists {
		oldVer.StoredKeyVersion().IsCurrent = false
	}

	// Store the new version.
	if _, ok := m.keyVersions[keyName]; !ok {
		m.keyVersions[keyName] = make(map[uint32]*key.KeyVersion)
	}
	m.keyVersions[keyName][nextVer] = version.Clone()

	// Update the parent key's current_version.
	k.StoredKey().CurrentVersion = nextVer
	return nil
}

func (m *MemoryStore) GetVersion(_ context.Context, keyName string, versionNumber uint32) (*key.KeyVersion, error) {
	const op errors.Op = "memory.(MemoryStore).GetVersion"
	m.mu.RLock()
	defer m.mu.RUnlock()
	versions, ok := m.keyVersions[keyName]
	if !ok {
		return nil, errors.New(context.Background(), op, errors.CodeKeyNotFound,
			"no versions for key: "+keyName)
	}
	v, ok := versions[versionNumber]
	if !ok {
		return nil, errors.New(context.Background(), op, errors.CodeKeyNotFound,
			"version not found")
	}
	return v.Clone(), nil
}

// Compile-time assertion.
// Note: the full Storage interface is NOT satisfied yet - only the key-related methods implemented so far.
// TODO:  Uncomment this assertion only after those steps are complete.
// var _ storage.Storage = (*MemoryStore)(nil)
