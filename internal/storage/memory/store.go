package memory

import (
	"context"
	"sync"

	"github.ibm.com/citius/citius-server/internal/crypto"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/provider"
)

const pkgName = "memory"

// MemoryStore is a goroutine-safe in-memory Storage implementation.
type MemoryStore struct {
	mu                sync.RWMutex
	keys              map[string]*key.Key
	keyVersions       map[string]map[uint32]*key.KeyVersion // keyName → versionNumber → version
	policies          map[string]*policy.Policy
	providerInstances map[string]*provider.Instance
	sessions          map[string]*crypto.Session
}

func New() *MemoryStore {
	return &MemoryStore{
		keys:              make(map[string]*key.Key),
		keyVersions:       make(map[string]map[uint32]*key.KeyVersion),
		policies:          make(map[string]*policy.Policy),
		providerInstances: make(map[string]*provider.Instance),
		sessions:          make(map[string]*crypto.Session),
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
	//TODO: Validation needed to prevent invalid state? For example, disallow updating current_version to a non-existent version number?
	// Or should that be the orchestrator's responsibility?
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

// ── Policy operations ──

func (m *MemoryStore) PutPolicy(_ context.Context, policy *policy.Policy) error {
	const op errors.Op = "memory.(MemoryStore).PutPolicy"
	if policy == nil {
		return errors.New(context.Background(), op, errors.CodeInvalidArgument, "policy must not be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[policy.PublicID()] = policy.Clone()
	return nil
}

func (m *MemoryStore) GetPolicy(_ context.Context, publicID string) (*policy.Policy, error) {
	const op errors.Op = "memory.(MemoryStore).GetPolicy"
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[publicID]
	if !ok {
		return nil, errors.New(context.Background(), op, errors.CodePolicyNotFound,
			"policy not found: "+publicID)
	}
	return p.Clone(), nil
}

func (m *MemoryStore) DeletePolicy(_ context.Context, publicID string) error {
	const op errors.Op = "memory.(MemoryStore).DeletePolicy"
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.policies[publicID]; !ok {
		return errors.New(context.Background(), op, errors.CodePolicyNotFound,
			"policy not found: "+publicID)
	}
	delete(m.policies, publicID)
	return nil
}

func (m *MemoryStore) ListPolicies(_ context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.policies))
	for id := range m.policies {
		out = append(out, id)
	}
	return out, nil
}

// ── ProviderInstance operations ──
func (m *MemoryStore) PutProviderInstance(_ context.Context, pi *provider.Instance) error {
	const op errors.Op = "memory.(MemoryStore).PutProviderInstance"
	if pi == nil {
		return errors.New(context.Background(), op, errors.CodeInvalidArgument, "provider instance must not be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providerInstances[pi.StoredProviderInstance().GetPublicId()] = pi.Clone()
	return nil
}

func (m *MemoryStore) GetProviderInstance(_ context.Context, publicID string) (*provider.Instance, error) {
	const op errors.Op = "memory.(MemoryStore).GetProviderInstance"
	m.mu.RLock()
	defer m.mu.RUnlock()
	pi, ok := m.providerInstances[publicID]
	if !ok {
		return nil, errors.New(context.Background(), op, errors.CodeProviderNotFound,
			"provider instance not found: "+publicID)
	}
	return pi.Clone(), nil
}

func (m *MemoryStore) DeleteProviderInstance(_ context.Context, publicID string) error {
	const op errors.Op = "memory.(MemoryStore).DeleteProviderInstance"
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.providerInstances[publicID]; !ok {
		return errors.New(context.Background(), op, errors.CodeProviderNotFound,
			"provider instance not found: "+publicID)
	}
	delete(m.providerInstances, publicID)
	return nil
}

func (m *MemoryStore) ListProviderInstances(_ context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.providerInstances))
	for id := range m.providerInstances {
		out = append(out, id)
	}
	return out, nil
}

// ── Session operations ──

func (m *MemoryStore) PutSession(_ context.Context, session *crypto.Session) error {
	const op errors.Op = "memory.(MemoryStore).PutSession"
	if session == nil {
		return errors.New(context.Background(), op, errors.CodeInvalidArgument, "session must not be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.StoredSession().GetPublicId()] = session.Clone()
	return nil
}

func (m *MemoryStore) GetSession(_ context.Context, publicID string) (*crypto.Session, error) {
	const op errors.Op = "memory.(MemoryStore).GetSession"
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[publicID]
	if !ok {
		return nil, errors.New(context.Background(), op, errors.CodeNotFound,
			"session not found: "+publicID)
	}
	return s.Clone(), nil
}

func (m *MemoryStore) DeleteSession(_ context.Context, publicID string) error {
	const op errors.Op = "memory.(MemoryStore).DeleteSession"
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[publicID]; !ok {
		return errors.New(context.Background(), op, errors.CodeNotFound,
			"session not found: "+publicID)
	}
	delete(m.sessions, publicID)
	return nil
}

func (m *MemoryStore) ListSessions(_ context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		out = append(out, id)
	}
	return out, nil
}

// Compile-time assertion.
// var _ storage.Storage = (*MemoryStore)(nil)
