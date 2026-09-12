package key

import "sync"

// VaultRepositoryOption configures VaultRepository construction. Kept local to
// this adapter (rather than on core/key.Option) because the name-to-ID cache
// factory centers on the unexported cache[T, V] interface, which only
// VaultRepository uses.
type VaultRepositoryOption func(*vaultRepositoryOptions)

type vaultRepositoryOptions struct {
	lock                 *sync.RWMutex
	keyNameToIDFunc      func(name string) (string, error)
	keyNameToIDCacheSize int
	cacheFactoryFunc     func(size int) cache[string, string]
}

func getVaultRepositoryOpts(opt ...VaultRepositoryOption) vaultRepositoryOptions {
	opts := vaultRepositoryOptions{
		lock:                 &sync.RWMutex{},
		keyNameToIDCacheSize: 1000,
		cacheFactoryFunc: func(size int) cache[string, string] {
			return newLRUCache[string, string](size)
		},
	}
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// WithLock provides an optional reference to a lock. VaultRepository
// instances can share the same lock so that per-request repositories
// sharing storage remain coordinated. Defaults to a new RWMutex.
func WithLock(lock *sync.RWMutex) VaultRepositoryOption {
	return func(o *vaultRepositoryOptions) {
		o.lock = lock
	}
}

// WithKeyNameToIDFunc overwrites the default name to id mapping behavior.
// By default, the repository stores a mapping from key name to public ID in
// vault, and uses that for name-based lookups. If this function is provided,
// it is used to resolve key names to IDs instead, and the repository does not
// store the mapping in vault. This can be used to integrate with an external
// system of record for key name to ID mapping, for example.
func WithKeyNameToIDFunc(f func(name string) (string, error)) VaultRepositoryOption {
	return func(o *vaultRepositoryOptions) {
		o.keyNameToIDFunc = f
	}
}

// WithKeyNameToIDCacheSize sets the cache size for name to id mapping; only
// used if WithKeyNameToIDFunc is not provided.
func WithKeyNameToIDCacheSize(size int) VaultRepositoryOption {
	return func(o *vaultRepositoryOptions) {
		o.keyNameToIDCacheSize = size
	}
}

// WithCacheFactoryFunc sets the factory function for creating the name to id
// cache. Defaults to an in-memory LRU cache. Only used if WithKeyNameToIDFunc
// is not provided.
func WithCacheFactoryFunc(f func(size int) cache[string, string]) VaultRepositoryOption {
	return func(o *vaultRepositoryOptions) {
		o.cacheFactoryFunc = f
	}
}
