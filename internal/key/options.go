package key

import (
	"sync"

	"github.ibm.com/citius/citius-server/gen/go/store"
)

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withLock                 *sync.RWMutex
	withTemplateID           string
	withStatus               store.KeyStatus
	withLabels               map[string]string
	withName                 string
	withWrappingKeyID        string
	withPublicID             string
	withDigestAlgorithm      string
	withCurrentVersion       uint32
	withInitialVersion       uint32
	withVetForWrite          bool
	withKeyNameToIdFunc      func(name string) (string, error)
	withKeyNameToIdCacheSize int
	withCacheFactoryFunc     func(size int) cache[string, string]
}

func getDefaultOptions() options {
	return options{
		withLock:                 &sync.RWMutex{},
		withStatus:               store.KeyStatus_KEY_STATUS_UNSPECIFIED,
		withLabels:               make(map[string]string),
		withDigestAlgorithm:      "HMAC-SHA256",
		withCurrentVersion:       0,
		withVetForWrite:          true, // default: vet for write
		withInitialVersion:       1,
		withKeyNameToIdFunc:      nil,
		withKeyNameToIdCacheSize: 1000,
		withCacheFactoryFunc: func(size int) cache[string, string] {
			return newLRUCache[string, string](size)
		},
	}
}

// WithLock provides an optional reference to a lock
func WithLock(lock *sync.RWMutex) Option {
	return func(o *options) {
		o.withLock = lock
	}
}

// WithTemplateID provides an optional template ID.
func WithTemplateID(templateID string) Option {
	return func(o *options) {
		o.withTemplateID = templateID
	}
}

// WithStatus provides an optional status.
func WithStatus(status store.KeyStatus) Option {
	return func(o *options) {
		o.withStatus = status
	}
}

// WithLabels provides optional labels.
func WithLabels(labels map[string]string) Option {
	return func(o *options) {
		o.withLabels = labels
	}
}

// WithName provides an optional name for a key
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}

func WithWrappingKeyID(wrappingKeyID string) Option {
	return func(o *options) {
		o.withWrappingKeyID = wrappingKeyID
	}
}

func WithKeyVersionID(versionID string) Option {
	return func(o *options) {
		o.withPublicID = versionID
	}
}

func WithCurrentVersion(version uint32) Option {
	return func(o *options) {
		o.withCurrentVersion = version
	}
}

func WithInitialVersion(version uint32) Option {
	return func(o *options) {
		o.withInitialVersion = version
	}
}

func WithVetForWrite(vet bool) Option {
	return func(o *options) {
		o.withVetForWrite = vet
	}
}

func WithKeyNameToIdFunc(f func(name string) (string, error)) Option {
	return func(o *options) {
		o.withKeyNameToIdFunc = f
	}
}

func WithKeyNameToIdCacheSize(size int) Option {
	return func(o *options) {
		o.withKeyNameToIdCacheSize = size
	}
}

func WithCacheFactoryFunc(f func(size int) cache[string, string]) Option {
	return func(o *options) {
		o.withCacheFactoryFunc = f
	}
}
