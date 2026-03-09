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
	mu   sync.RWMutex
	keys map[string]*key.Key
	// keyVersions, policies, sessions, providerInstances to be added
}

func New() *MemoryStore {
	return &MemoryStore{
		keys: make(map[string]*key.Key),
	}
}

// ---- Key operations ----

func (m *MemoryStore) PutKey(_ context.Context, key *key.Key) error {
	const op errors.Op = "memory.(MemoryStore).PutKey"
	if key == nil {
		return errors.New(context.Background(), op, errors.CodeInvalidArgument, "key must not be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[key.PublicID()] = key.Clone()
	return nil
}

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

func (m *MemoryStore) DeleteKey(_ context.Context, publicID string) error {
	const op errors.Op = "memory.(MemoryStore).DeleteKey"
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[publicID]; !ok {
		return errors.New(context.Background(), op, errors.CodeKeyNotFound,
			"key not found: "+publicID)
	}
	delete(m.keys, publicID)
	return nil
}

func (m *MemoryStore) ListKeys(_ context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.keys))
	for name := range m.keys {
		out = append(out, name)
	}
	return out, nil
}

func (m *MemoryStore) UpdateKey(_ context.Context, key *key.Key) error {
	const op errors.Op = "memory.(MemoryStore).UpdateKey"
	if key == nil {
		return errors.New(context.Background(), op, errors.CodeInvalidArgument, "key must not be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[key.PublicID()]; !ok {
		return errors.New(context.Background(), op, errors.CodeKeyNotFound,
			"key not found: "+key.PublicID())
	}
	m.keys[key.PublicID()] = key.Clone()
	return nil
}

// Compile-time assertion.
// Note: the full Storage interface is NOT satisfied yet - only the key-related methods implemented so far.
// TODO:  Uncomment this assertion only after those steps are complete.
// var _ storage.Storage = (*MemoryStore)(nil)
