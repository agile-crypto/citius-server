package storage

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/sdk/logical"
	"github.ibm.com/citius/citius-server/internal/errors"
)

type InMemoryStorage struct {
	mu *sync.RWMutex
	*logical.InmemStorage
}

var _ Storage = (*InMemoryStorage)(nil)

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		mu:           &sync.RWMutex{},
		InmemStorage: &logical.InmemStorage{},
	}
}

func (s *InMemoryStorage) DoTx(ctx context.Context, handler TxHandler) error {
	const op = "storage.(InMemoryStorage).DoTx"
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := handler(s); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}
