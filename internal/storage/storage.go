package storage

import (
	"context"
)

// // Storage composes all aggregate repository interfaces.
// // Implementations must be goroutine-safe.
// type Storage interface {
// 	key.Repository
// 	policy.Repository
// 	provider.InstanceRepository
// 	crypto.SessionRepository
// }

// Storage is a generic interface for storing and retrieving values of any type.
// Expected implementations include in-memory and Vault storage backends.
// Implementations are not expected to be thread-safe.
type Storage[T any] interface {
	// Yields a list of keys
	List(ctx context.Context) ([]string, error)
	// Returns nil if the key does not exist
	Get(ctx context.Context, key string) (T, error)
	// Override existing key if it exists, otherwise create a new one
	Put(ctx context.Context, key string, value T) error
	// Delete the key if it exists, otherwise do nothing
	Delete(ctx context.Context, key string) error
}
