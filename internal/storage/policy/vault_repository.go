package policy

import (
	"context"
	"sync"

	corepolicy "github.com/agile-crypto/citius-core/policy"

	"github.com/agile-crypto/citius-core/errors"
	storepb "github.com/agile-crypto/citius-core/store"
	"github.com/agile-crypto/citius-server/internal/storage"
	"google.golang.org/protobuf/proto"
)

const policyStoragePrefix = "policy/"

var _ corepolicy.Repository = (*StorageRepository)(nil)

type StorageRepository struct {
	mu       *sync.RWMutex
	policies storage.Storage
}

func NewStorageRepository(ctx context.Context, store storage.Storage, opt ...corepolicy.Option) (*StorageRepository, error) {
	const op errors.Op = "policy.NewStorageRepository"
	if store == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "nil storage")
	}
	opts := corepolicy.GetVaultOptions(opt...)
	return &StorageRepository{
		mu:       opts.Lock,
		policies: storage.NewView(store, policyStoragePrefix),
	}, nil
}

func (r *StorageRepository) PutPolicy(ctx context.Context, p *corepolicy.Policy) error {
	const op errors.Op = "policy.(StorageRepository).PutPolicy"
	if p == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "policy must not be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, err := proto.Marshal(p.StoredPolicy())
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	entry := &storage.Entry{Key: p.Name(), Value: b}
	if err := r.policies.Put(ctx, entry); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *StorageRepository) GetPolicy(ctx context.Context, name string) (*corepolicy.Policy, error) {
	const op errors.Op = "policy.(StorageRepository).GetPolicy"
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, err := r.policies.Get(ctx, name)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return nil, errors.New(ctx, op, errors.CodePolicyNotFound, "policy not found: "+name)
	}
	stored := &storepb.StoredPolicy{}
	if err := proto.Unmarshal(entry.Value, stored); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return corepolicy.New(stored), nil
}

func (r *StorageRepository) DeletePolicy(ctx context.Context, name string) error {
	const op errors.Op = "policy.(StorageRepository).DeletePolicy"
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, err := r.policies.Get(ctx, name)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return errors.New(ctx, op, errors.CodePolicyNotFound, "policy not found: "+name)
	}
	return r.policies.Delete(ctx, name)
}

func (r *StorageRepository) ListPolicies(ctx context.Context) ([]string, error) {
	const op errors.Op = "policy.(StorageRepository).ListPolicies"
	r.mu.RLock()
	defer r.mu.RUnlock()

	names, err := r.policies.List(ctx, "")
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}
