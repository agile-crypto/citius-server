package storage

import (
	"context"
)

// InMemoryStorage implements the Storage interface using an in-memory map.
// It is not thread-safe.
type InMemoryStorage[T any] struct {
	data map[string]T
}

var _ Storage[any] = (*InMemoryStorage[any])(nil)

// NewInMemoryStorage creates a new in-memory storage instance.
func NewInMemoryStorage[T any]() *InMemoryStorage[T] {
	return &InMemoryStorage[T]{
		data: make(map[string]T),
	}
}

// List returns all keys in the storage.
func (s *InMemoryStorage[T]) List(ctx context.Context) ([]string, error) {
	keys := make([]string, 0, len(s.data))
	for k := range s.data {
		keys = append(keys, k)
	}
	return keys, nil
}

// Get retrieves a value by key. Returns the zero value of T if the key does not exist.
func (s *InMemoryStorage[T]) Get(ctx context.Context, key string) (T, error) {
	return s.data[key], nil
}

// Put stores or updates a value for a key.
func (s *InMemoryStorage[T]) Put(ctx context.Context, key string, value T) error {
	s.data[key] = value
	return nil
}

// Delete removes a key from the storage. Does nothing if the key does not exist.
func (s *InMemoryStorage[T]) Delete(ctx context.Context, key string) error {
	delete(s.data, key)
	return nil
}
