package vaultstorage_test

import (
	"context"
	"testing"

	corepolicy "github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-server/vault-storage/key"
	"github.com/agile-crypto/citius-server/vault-storage/policy"
	"github.com/agile-crypto/citius-server/vault-storage/provider"
	"github.com/agile-crypto/citius-server/vault-storage/template"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The constructors are thin: they adapt a logical.Storage and delegate to the
// repositories in internal/storage, whose behaviour is tested there. These
// tests check the delegation and that nil Vault storage is still rejected.

func TestConstructors_overLogicalInmem_succeed(t *testing.T) {
	ctx := context.Background()
	s := &logical.InmemStorage{}

	k, err := key.NewVaultRepository(ctx, s)
	require.NoError(t, err)
	assert.NotNil(t, k)

	p, err := policy.NewVaultRepository(ctx, s)
	require.NoError(t, err)
	assert.NotNil(t, p)

	pi, err := provider.NewVaultRepository(ctx, s)
	require.NoError(t, err)
	assert.NotNil(t, pi)

	tr, err := template.NewVaultRegistry(ctx, s)
	require.NoError(t, err)
	assert.NotNil(t, tr)
}

func TestConstructors_nilStorage_returnError(t *testing.T) {
	ctx := context.Background()

	_, err := key.NewVaultRepository(ctx, nil)
	require.Error(t, err)
	_, err = policy.NewVaultRepository(ctx, nil)
	require.Error(t, err)
	_, err = provider.NewVaultRepository(ctx, nil)
	require.Error(t, err)
	_, err = template.NewVaultRegistry(ctx, nil)
	require.Error(t, err)
}

func TestPolicyRepository_writesThroughToVaultStorage(t *testing.T) {
	ctx := context.Background()
	s := &logical.InmemStorage{}

	r, err := policy.NewVaultRepository(ctx, s)
	require.NoError(t, err)
	require.NoError(t, r.PutPolicy(ctx, corepolicy.NewPolicy("", "p1", nil)))

	// The repository's "policy/" view must land in the Vault storage itself.
	keys, err := s.List(ctx, "policy/")
	require.NoError(t, err)
	assert.Equal(t, []string{"p1"}, keys)

	got, err := r.GetPolicy(ctx, "p1")
	require.NoError(t, err)
	assert.Equal(t, "p1", got.Name())
}
