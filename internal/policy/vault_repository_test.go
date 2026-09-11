package policy_test

import (
	"context"
	"testing"

	corepolicy "github.com/agile-crypto/citius-core/policy"

	"github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-server/internal/policy"
	"github.com/hashicorp/vault/sdk/logical"
)

func newTestPolicy(name string) *corepolicy.Policy {
	return corepolicy.NewPolicy("", name, nil)
}

var repoFn = func() corepolicy.Repository {
	storage := &logical.InmemStorage{}
	r, err := policy.NewVaultRepository(context.Background(), storage)
	if err != nil {
		panic("failed to create policy VaultRepository: " + err.Error())
	}
	return r
}

func Test_PolicyVaultRepository_PutPolicy_GetPolicy_roundtrip(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	p := newTestPolicy("default-sig-policy")

	if err := r.PutPolicy(ctx, p); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	got, err := r.GetPolicy(ctx, "default-sig-policy")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.Name() != "default-sig-policy" {
		t.Errorf("Name: got %q want %q", got.Name(), "default-sig-policy")
	}
}

func Test_PolicyVaultRepository_GetPolicy_notFound(t *testing.T) {
	r := repoFn()
	_, err := r.GetPolicy(context.Background(), "pol_doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing policy")
	}
	if !errors.IsPolicyNotFound(err) {
		t.Errorf("expected PolicyNotFound, got: %v", err)
	}
}

func Test_PolicyVaultRepository_DeletePolicy_success(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	_ = r.PutPolicy(ctx, newTestPolicy("p"))
	if err := r.DeletePolicy(ctx, "p"); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	_, err := r.GetPolicy(ctx, "p")
	if !errors.IsPolicyNotFound(err) {
		t.Errorf("expected PolicyNotFound after delete, got: %v", err)
	}
}

func Test_PolicyVaultRepository_ListPolicies_all(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	_ = r.PutPolicy(ctx, newTestPolicy("p1"))
	_ = r.PutPolicy(ctx, newTestPolicy("p2"))

	names, err := r.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("ListPolicies: got %d want 2", len(names))
	}
}

func Test_PolicyVaultRepository_ListPolicies_empty(t *testing.T) {
	r := repoFn()
	names, err := r.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if names == nil {
		t.Error("ListPolicies should return empty slice, not nil")
	}
}

func Test_PolicyVaultRepository_PutPolicy_nil_returnsError(t *testing.T) {
	r := repoFn()
	if err := r.PutPolicy(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil policy")
	}
}

func Test_PolicyVaultRepository_GetPolicy_returnsClone(t *testing.T) {
	r := repoFn()
	ctx := context.Background()
	_ = r.PutPolicy(ctx, newTestPolicy("original"))
	got, _ := r.GetPolicy(ctx, "original")
	got.StoredPolicy().Name = "mutated"
	got2, _ := r.GetPolicy(ctx, "original")
	if got2.Name() != "original" {
		t.Error("GetPolicy should return an independent copy (proto round-trip)")
	}
}
