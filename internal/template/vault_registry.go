package template

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/sdk/logical"
	api "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"google.golang.org/protobuf/proto"
)

const templateStoragePrefix = "template/"

var _ Registry = (*VaultRegistry)(nil)

// VaultRegistry is a Vault-backed implementation of the Registry interface.
// Uses logical.Storage (typically logical.InmemStorage) with proto serialization,
// following the same pattern as VaultRepository in key, policy, and provider.
type VaultRegistry struct {
	mu        *sync.RWMutex
	templates logical.Storage
}

// NewVaultRegistry creates a VaultRegistry backed by the given storage.
// For in-memory usage, pass &logical.InmemStorage{}.
func NewVaultRegistry(ctx context.Context, storage logical.Storage, opt ...Option) (*VaultRegistry, error) {
	const op errors.Op = "template.NewVaultRegistry"
	if storage == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "nil storage")
	}
	opts := getOpts(opt...)
	return &VaultRegistry{
		mu:        opts.withLock,
		templates: logical.NewStorageView(storage, templateStoragePrefix),
	}, nil
}

// Register stores a template. If a template with the same ID already exists,
// it is overwritten (permits startup re-loading).
func (r *VaultRegistry) Register(ctx context.Context, t *Template) error {
	const op errors.Op = "template.(VaultRegistry).Register"
	if t == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "template must not be nil")
	}
	if t.TemplateID() == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "template ID must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, err := proto.Marshal(t.stored)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	entry := &logical.StorageEntry{Key: t.TemplateID(), Value: b}
	if err := r.templates.Put(ctx, entry); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// Get returns the template with the given ID, or a CodeTemplateNotFound error.
// Returns an independent copy via proto round-trip (marshal on Register, unmarshal on Get).
func (r *VaultRegistry) Get(ctx context.Context, templateID string) (*Template, error) {
	const op errors.Op = "template.(VaultRegistry).Get"
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, err := r.templates.Get(ctx, templateID)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return nil, errors.New(ctx, op, errors.CodeTemplateNotFound,
			"template not found: "+templateID)
	}
	stored := &api.TemplateInfo{}
	if err := proto.Unmarshal(entry.Value, stored); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return NewTemplate(stored), nil
}

// List returns all registered templates.
func (r *VaultRegistry) List(ctx context.Context) []*Template {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids, err := r.templates.List(ctx, "")
	if err != nil {
		return []*Template{}
	}
	out := make([]*Template, 0, len(ids))
	for _, id := range ids {
		entry, err := r.templates.Get(ctx, id)
		if err != nil || entry == nil {
			continue
		}
		stored := &api.TemplateInfo{}
		if err := proto.Unmarshal(entry.Value, stored); err != nil {
			continue
		}
		out = append(out, NewTemplate(stored))
	}
	return out
}

// TODO: Select to be implemented. Stub returns ErrNotImplemented.
func (r *VaultRegistry) Select(_ context.Context, _ core.ScopeSpec, _ []string, _ map[string]string) (*Template, error) {
	const op errors.Op = "template.(VaultRegistry).Select"
	return nil, errors.New(nil, op, errors.CodeNotImplemented,
		"Select not yet implemented")
}
