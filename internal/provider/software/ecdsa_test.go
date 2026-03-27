package software_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
	types "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/provider/software"
)

// ecdsaP256Details returns an AlgorithmDetails for ECDSA-P256-SHA256.
func ecdsaP256Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{
				Curve: types.EllipticCurve_ELLIPTIC_CURVE_P256,
				Hash:  types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			},
		},
	}
}

// mlDSA65Details returns an AlgorithmDetails for ML-DSA-65.
func mlDSA65Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_MlDsa{
			MlDsa: &types.MlDsaParams{
				ParameterSet: types.MlDsaParameterSet_ML_DSA_65,
			},
		},
	}
}

// ============================================================================
// ECDSA-P256 Key Generation Tests
// ============================================================================

func TestGenerateKey_ECDSA_P256_happyPath(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	resp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{
		Algorithm: ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(resp.GetPublicKeyBytes()) == 0 {
		t.Error("expected non-empty public key bytes")
	}
	if len(resp.GetKeyMaterial()) == 0 {
		t.Error("expected non-empty key material")
	}
}

func TestGenerateKey_ECDSA_P256_publicKeyIsDERParseable(t *testing.T) {
	p := software.New()
	resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pub, err := x509.ParsePKIXPublicKey(resp.GetPublicKeyBytes())
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if ecPub.Curve.Params().Name != "P-256" {
		t.Errorf("curve: got %q want %q", ecPub.Curve.Params().Name, "P-256")
	}
}

func TestGenerateKey_ECDSA_P256_privateKeyIsDERParseable(t *testing.T) {
	p := software.New()
	resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	priv, err := x509.ParseECPrivateKey(resp.GetKeyMaterial())
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}
	if priv.Curve.Params().Name != "P-256" {
		t.Errorf("curve: got %q want %q", priv.Curve.Params().Name, "P-256")
	}
}

func TestGenerateKey_ECDSA_P256_keysAreUnique(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	r1, _ := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})
	r2, _ := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: ecdsaP256Details()})

	if string(r1.GetPublicKeyBytes()) == string(r2.GetPublicKeyBytes()) {
		t.Error("two generated keys should not be identical")
	}
}

func TestGenerateKey_MLDSA65_stillNotImplemented(t *testing.T) {
	p := software.New()
	_, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: mlDSA65Details(),
	})
	if err == nil {
		t.Fatal("expected error for ml-dsa-65 (not yet implemented in this step)")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented for ml-dsa-65, got: %v", err)
	}
}

func TestGenerateKey_unknownAlgorithm_returnsError(t *testing.T) {
	p := software.New()
	_, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: &types.AlgorithmDetails{
			Algorithm: &types.AlgorithmDetails_RsaPss{
				RsaPss: &types.RsaPssParams{},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}
