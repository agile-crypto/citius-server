package policy

import (
	"context"
	"sync"

	corepolicy "github.com/agile-crypto/citius-core/policy"

	"github.com/agile-crypto/citius-core/errors"
	storepb "github.com/agile-crypto/citius-core/store"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/protobuf/proto"
)

const policyStoragePrefix = "policy/"

var _ corepolicy.Repository = (*VaultRepository)(nil)

type VaultRepository struct {
	mu       *sync.RWMutex
	policies logical.Storage
}

func NewVaultRepository(ctx context.Context, storage logical.Storage, opt ...corepolicy.Option) (*VaultRepository, error) {
	const op errors.Op = "policy.NewVaultRepository"
	if storage == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "nil storage")
	}
	opts := corepolicy.GetVaultOptions(opt...)
	return &VaultRepository{
		mu:       opts.Lock,
		policies: logical.NewStorageView(storage, policyStoragePrefix),
	}, nil
}

func (r *VaultRepository) PutPolicy(ctx context.Context, p *corepolicy.Policy) error {
	const op errors.Op = "policy.(VaultRepository).PutPolicy"
	if p == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "policy must not be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, err := proto.Marshal(p.StoredPolicy())
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	entry := &logical.StorageEntry{Key: p.Name(), Value: b}
	if err := r.policies.Put(ctx, entry); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *VaultRepository) GetPolicy(ctx context.Context, name string) (*corepolicy.Policy, error) {
	const op errors.Op = "policy.(VaultRepository).GetPolicy"
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

func (r *VaultRepository) DeletePolicy(ctx context.Context, name string) error {
	const op errors.Op = "policy.(VaultRepository).DeletePolicy"
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

func (r *VaultRepository) ListPolicies(ctx context.Context) ([]string, error) {
	const op errors.Op = "policy.(VaultRepository).ListPolicies"
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
