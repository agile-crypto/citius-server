package key

import "sync"

// StorageRepositoryOption configures StorageRepository construction. Kept local to
// this adapter (rather than on core/key.Option) because the name-to-ID cache
// factory centers on the unexported cache[T, V] interface, which only
// StorageRepository uses.
type StorageRepositoryOption func(*storageRepositoryOptions)

type storageRepositoryOptions struct {
	lock                 *sync.RWMutex
	keyNameToIDFunc      func(name string) (string, error)
	keyNameToIDCacheSize int
	cacheFactoryFunc     func(size int) cache[string, string]
}

func getStorageRepositoryOpts(opt ...StorageRepositoryOption) storageRepositoryOptions {
	opts := storageRepositoryOptions{
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

// WithLock provides an optional reference to a lock. StorageRepository
// instances can share the same lock so that per-request repositories
// sharing storage remain coordinated. Defaults to a new RWMutex.
func WithLock(lock *sync.RWMutex) StorageRepositoryOption {
	return func(o *storageRepositoryOptions) {
		o.lock = lock
	}
}

// WithKeyNameToIDFunc overwrites the default name to id mapping behavior.
// By default, the repository stores a mapping from key name to public ID in
// vault, and uses that for name-based lookups. If this function is provided,
// it is used to resolve key names to IDs instead, and the repository does not
// store the mapping in vault. This can be used to integrate with an external
// system of record for key name to ID mapping, for example.
func WithKeyNameToIDFunc(f func(name string) (string, error)) StorageRepositoryOption {
	return func(o *storageRepositoryOptions) {
		o.keyNameToIDFunc = f
	}
}

// WithKeyNameToIDCacheSize sets the cache size for name to id mapping; only
// used if WithKeyNameToIDFunc is not provided.
func WithKeyNameToIDCacheSize(size int) StorageRepositoryOption {
	return func(o *storageRepositoryOptions) {
		o.keyNameToIDCacheSize = size
	}
}

// WithCacheFactoryFunc sets the factory function for creating the name to id
// cache. Defaults to an in-memory LRU cache. Only used if WithKeyNameToIDFunc
// is not provided.
func WithCacheFactoryFunc(f func(size int) cache[string, string]) StorageRepositoryOption {
	return func(o *storageRepositoryOptions) {
		o.cacheFactoryFunc = f
	}
}
