package template_test

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	api "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/template"
)

func ecdsaTemplate() *template.Template {
	return template.NewTemplate(&api.TemplateInfo{
		TemplateId: "ecdsa-p256-sha256",
		Algorithm: &api.AlgorithmDetails{
			Algorithm: &api.AlgorithmDetails_Ecdsa{
				Ecdsa: &api.EcdsaParams{
					Curve: api.EllipticCurve_ELLIPTIC_CURVE_P256,
					Hash:  api.HashAlgorithm_HASH_ALGORITHM_SHA256,
				},
			},
		},
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
					},
				},
			},
			Operations: []api.CryptoOperation{
				api.CryptoOperation_CRYPTO_OPERATION_SIGN,
				api.CryptoOperation_CRYPTO_OPERATION_VERIFY,
			},
		}},
		Status: api.TemplateStatus_TEMPLATE_STATUS_ACTIVE,
	})
}

func mldsaTemplate() *template.Template {
	return template.NewTemplate(&api.TemplateInfo{
		TemplateId: "ml-dsa-65",
		Algorithm: &api.AlgorithmDetails{
			Algorithm: &api.AlgorithmDetails_MlDsa{
				MlDsa: &api.MlDsaParams{
					ParameterSet: api.MlDsaParameterSet_ML_DSA_65,
				},
			},
		},
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
					},
				},
			},
			Operations: []api.CryptoOperation{
				api.CryptoOperation_CRYPTO_OPERATION_SIGN,
				api.CryptoOperation_CRYPTO_OPERATION_VERIFY,
			},
		}},
		Status: api.TemplateStatus_TEMPLATE_STATUS_ACTIVE,
	})
}

var registryFn = func() template.Registry {
	storage := &logical.InmemStorage{}
	r, err := template.NewVaultRegistry(context.Background(), storage)
	if err != nil {
		panic("failed to create template VaultRegistry: " + err.Error())
	}
	return r
}

// ============================================================================
// Register Tests
// ============================================================================

func TestVaultRegistry_Register_success(t *testing.T) {
	r := registryFn()
	if err := r.Register(context.Background(), ecdsaTemplate()); err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func TestVaultRegistry_Register_nil_returnsError(t *testing.T) {
	r := registryFn()
	if err := r.Register(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil template")
	}
}

func TestVaultRegistry_Register_emptyID_returnsError(t *testing.T) {
	r := registryFn()
	tmpl := template.NewTemplate(&api.TemplateInfo{TemplateId: ""})
	if err := r.Register(context.Background(), tmpl); err == nil {
		t.Fatal("expected error for empty template ID")
	}
}

func TestVaultRegistry_Register_duplicate_overwrite(t *testing.T) {
	r := registryFn()
	_ = r.Register(context.Background(), ecdsaTemplate())
	updated := template.NewTemplate(&api.TemplateInfo{
		TemplateId:  "ecdsa-p256-sha256",
		DisplayName: "Updated ECDSA",
		Algorithm: &api.AlgorithmDetails{
			Algorithm: &api.AlgorithmDetails_Ecdsa{
				Ecdsa: &api.EcdsaParams{
					Curve: api.EllipticCurve_ELLIPTIC_CURVE_P256,
					Hash:  api.HashAlgorithm_HASH_ALGORITHM_SHA256,
				},
			},
		},
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
					},
				},
			},
		}},
		Status: api.TemplateStatus_TEMPLATE_STATUS_ACTIVE,
	})
	if err := r.Register(context.Background(), updated); err != nil {
		t.Fatalf("second Register: %v", err)
	}
	got, _ := r.Get(context.Background(), "ecdsa-p256-sha256")
	if got.GetDisplayName() != "Updated ECDSA" {
		t.Errorf("DisplayName: got %q want %q", got.GetDisplayName(), "Updated ECDSA")
	}
}

// ============================================================================
// Get Tests
// ============================================================================

func TestVaultRegistry_Get_success(t *testing.T) {
	r := registryFn()
	_ = r.Register(context.Background(), ecdsaTemplate())
	got, err := r.Get(context.Background(), "ecdsa-p256-sha256")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.TemplateID() != "ecdsa-p256-sha256" {
		t.Errorf("TemplateID: got %q want %q", got.TemplateID(), "ecdsa-p256-sha256")
	}
	if got.GetStatus() != api.TemplateStatus_TEMPLATE_STATUS_ACTIVE {
		t.Error("expected Status=TEMPLATE_STATUS_ACTIVE")
	}
}

func TestVaultRegistry_Get_notFound(t *testing.T) {
	r := registryFn()
	_, err := r.Get(context.Background(), "no-such-template")
	if err == nil {
		t.Fatal("expected error for missing template")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound error, got: %v", err)
	}
}

func TestVaultRegistry_Get_returnsClone(t *testing.T) {
	r := registryFn()
	_ = r.Register(context.Background(), ecdsaTemplate())
	got, _ := r.Get(context.Background(), "ecdsa-p256-sha256")
	got.StoredTemplate().TemplateId = "mutated"
	// Re-fetch should still have original value (proto round-trip gives independent copy)
	got2, _ := r.Get(context.Background(), "ecdsa-p256-sha256")
	if got2.TemplateID() != "ecdsa-p256-sha256" {
		t.Error("Get should return an independent copy (proto round-trip)")
	}
}

// ============================================================================
// List Tests
// ============================================================================

func TestVaultRegistry_List_all(t *testing.T) {
	r := registryFn()
	_ = r.Register(context.Background(), ecdsaTemplate())
	_ = r.Register(context.Background(), mldsaTemplate())
	list := r.List(context.Background())
	if len(list) != 2 {
		t.Errorf("List: got %d want 2", len(list))
	}
}

func TestVaultRegistry_List_empty(t *testing.T) {
	r := registryFn()
	list := r.List(context.Background())
	if list == nil {
		t.Error("List should return empty slice, not nil")
	}
}

// ============================================================================
// Select stub (TODO: not implemented, just returns NotImplemented error)
// ============================================================================

func TestVaultRegistry_Select_stub_notImplemented(t *testing.T) {
	r := registryFn()
	_ = r.Register(context.Background(), ecdsaTemplate())
	_, err := r.Select(context.Background(), core.ScopeSpec{}, nil, nil)
	if err == nil {
		t.Fatal("expected error for unimplemented Select")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected NotImplemented error, got: %v", err)
	}
}
