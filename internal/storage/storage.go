package storage

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

type TxHandler func(Storage) error
type Storage interface {
	logical.Storage
	DoTx(context.Context, TxHandler) error
}
