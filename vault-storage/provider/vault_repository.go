package provider

import (
	"context"
	"sync"

	coreprovider "github.com/agile-crypto/citius-core/provider"

	"github.com/agile-crypto/citius-core/errors"
	storepb "github.com/agile-crypto/citius-core/store"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/protobuf/proto"
)

const providerInstanceStoragePrefix = "provider_instance/"

var _ coreprovider.InstanceRepository = (*VaultRepository)(nil)

type VaultRepository struct {
	mu        *sync.RWMutex
	instances logical.Storage
}

func NewVaultRepository(ctx context.Context, storage logical.Storage, opt ...coreprovider.Option) (*VaultRepository, error) {
	const op errors.Op = "provider.NewVaultRepository"
	if storage == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "nil storage")
	}
	opts := coreprovider.GetVaultOptions(opt...)
	return &VaultRepository{
		mu:        opts.Lock,
		instances: logical.NewStorageView(storage, providerInstanceStoragePrefix),
	}, nil
}

func (r *VaultRepository) PutProviderInstance(ctx context.Context, instance *coreprovider.Instance) error {
	const op errors.Op = "provider.(VaultRepository).PutProviderInstance"
	if instance == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "instance must not be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, err := proto.Marshal(instance.StoredProviderInstance())
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	entry := &logical.StorageEntry{Key: instance.PublicID(), Value: b}
	if err := r.instances.Put(ctx, entry); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *VaultRepository) GetProviderInstance(ctx context.Context, publicID string) (*coreprovider.Instance, error) {
	const op errors.Op = "provider.(VaultRepository).GetProviderInstance"
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, err := r.instances.Get(ctx, publicID)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return nil, errors.New(ctx, op, errors.CodeProviderNotFound, "provider instance not found: "+publicID)
	}
	stored := &storepb.StoredProviderInstance{}
	if err := proto.Unmarshal(entry.Value, stored); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return coreprovider.NewInstance(stored), nil
}

func (r *VaultRepository) DeleteProviderInstance(ctx context.Context, publicID string) error {
	const op errors.Op = "provider.(VaultRepository).DeleteProviderInstance"
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, err := r.instances.Get(ctx, publicID)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return errors.New(ctx, op, errors.CodeProviderNotFound, "provider instance not found: "+publicID)
	}
	return r.instances.Delete(ctx, publicID)
}

func (r *VaultRepository) ListProviderInstances(ctx context.Context) ([]string, error) {
	const op errors.Op = "provider.(VaultRepository).ListProviderInstances"
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids, err := r.instances.List(ctx, "")
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if ids == nil {
		ids = []string{}
	}
	return ids, nil
}
