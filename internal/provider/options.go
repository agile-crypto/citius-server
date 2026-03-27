package provider

import "sync"

func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

type Option func(*options)

type options struct {
	withLock *sync.RWMutex
}

func getDefaultOptions() options {
	return options{
		withLock: &sync.RWMutex{},
	}
}

// WithLock provides an optional reference to a lock
func WithLock(lock *sync.RWMutex) Option {
	return func(o *options) {
		o.withLock = lock
	}
}
