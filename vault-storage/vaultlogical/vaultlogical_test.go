package vaultlogical_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/citius-server/internal/storage"
	"github.com/agile-crypto/citius-server/vault-storage/vaultlogical"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromLogical_nil_returnsNil(t *testing.T) {
	assert.Nil(t, vaultlogical.FromLogical(nil))
}

func TestAdapter_roundTrip(t *testing.T) {
	ctx := context.Background()
	inner := &logical.InmemStorage{}
	s := vaultlogical.FromLogical(inner)

	require.NoError(t, s.Put(ctx, &storage.Entry{Key: "a/b", Value: []byte("v")}))

	raw, err := inner.Get(ctx, "a/b")
	require.NoError(t, err)
	require.NotNil(t, raw)
	assert.Equal(t, []byte("v"), raw.Value)

	e, err := s.Get(ctx, "a/b")
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Equal(t, "a/b", e.Key)
	assert.Equal(t, []byte("v"), e.Value)

	missing, err := s.Get(ctx, "nope")
	require.NoError(t, err)
	assert.Nil(t, missing)

	require.NoError(t, s.Delete(ctx, "a/b"))
	e, err = s.Get(ctx, "a/b")
	require.NoError(t, err)
	assert.Nil(t, e)
}

// TestInmemStorage_listParityWithVault checks that our in-memory storage,
// directly and through a View, lists exactly what Vault's InmemStorage and
// StorageView list for the same keys.
func TestInmemStorage_listParityWithVault(t *testing.T) {
	ctx := context.Background()
	keys := []string{
		"b", "a", "a/x", "a/y/z", "a/y/w", "a0", "a-x", "c/d", "c/e/f",
		"key/k1", "key/k2", "key_version/id1:1", "key_version/id1:2",
		"key_version/id10:1", "key_version/id1/x", "policy/p", "",
	}
	prefixes := []string{
		"", "a", "a/", "a/y/", "c/", "key/", "key_version/",
		"key_version/id1:", "key_version/id1", "missing/", "z",
	}

	ours := storage.NewInmemStorage()
	vault := vaultlogical.FromLogical(&logical.InmemStorage{})
	for _, k := range keys {
		e := &storage.Entry{Key: k, Value: []byte(k)}
		require.NoError(t, ours.Put(ctx, e))
		require.NoError(t, vault.Put(ctx, e))
	}

	for _, p := range prefixes {
		want, err := vault.List(ctx, p)
		require.NoError(t, err)
		got, err := ours.List(ctx, p)
		require.NoError(t, err)
		assert.Equal(t, want, got, "List(%q)", p)
	}

	// Views: compare ours over ours with Vault's StorageView over Vault.
	vaultInner := &logical.InmemStorage{}
	oursInner := storage.NewInmemStorage()
	for _, k := range keys {
		require.NoError(t, vaultInner.Put(ctx, &logical.StorageEntry{Key: k, Value: []byte(k)}))
		require.NoError(t, oursInner.Put(ctx, &storage.Entry{Key: k, Value: []byte(k)}))
	}
	for _, viewPrefix := range []string{"key/", "key_version/", "a/"} {
		vv := vaultlogical.FromLogical(logical.NewStorageView(vaultInner, viewPrefix))
		ov := storage.NewView(oursInner, viewPrefix)
		for _, p := range prefixes {
			want, err := vv.List(ctx, p)
			require.NoError(t, err)
			got, err := ov.List(ctx, p)
			require.NoError(t, err)
			assert.Equal(t, want, got, "view %q List(%q)", viewPrefix, p)
		}
	}
}

// recordingStorage is a logical.Storage that keeps entries verbatim.
// Vault's InmemStorage cannot be used here: it drops SealWrap.
type recordingStorage struct {
	logical.InmemStorage
	entries map[string]logical.StorageEntry
}

func (r *recordingStorage) Put(_ context.Context, e *logical.StorageEntry) error {
	r.entries[e.Key] = *e
	return nil
}

func (r *recordingStorage) Get(_ context.Context, key string) (*logical.StorageEntry, error) {
	e, ok := r.entries[key]
	if !ok {
		return nil, nil
	}
	return &e, nil
}

func TestAdapter_sealWrap_passedThrough(t *testing.T) {
	ctx := context.Background()
	inner := &recordingStorage{entries: map[string]logical.StorageEntry{}}
	s := vaultlogical.FromLogical(inner)

	require.NoError(t, s.Put(ctx, &storage.Entry{Key: "w", Value: []byte("v"), SealWrap: true}))
	assert.True(t, inner.entries["w"].SealWrap, "Put must forward SealWrap to Vault")

	inner.entries["r"] = logical.StorageEntry{Key: "r", Value: []byte("v"), SealWrap: true}
	e, err := s.Get(ctx, "r")
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.True(t, e.SealWrap, "Get must surface SealWrap from Vault")
}
