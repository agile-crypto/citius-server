package software_test

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/provider/software"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ============================================================================
// ML-DSA-65 Key Generation Tests
// ============================================================================

func TestGenerateKey_MLDSA65_happyPath(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	resp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{
		Algorithm: mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey ml-dsa-65: %v", err)
	}
	if len(resp.GetPublicKeyBytes()) == 0 {
		t.Error("expected non-empty public key bytes")
	}
	if len(resp.GetKeyMaterial()) == 0 {
		t.Error("expected non-empty key material (private key bytes)")
	}
}

func TestGenerateKey_MLDSA65_publicKeyIsCorrectSize(t *testing.T) {
	p := software.New()
	resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(resp.GetPublicKeyBytes()) != mldsa65.PublicKeySize {
		t.Errorf("public key size: got %d want %d", len(resp.GetPublicKeyBytes()), mldsa65.PublicKeySize)
	}
}

func TestGenerateKey_MLDSA65_privateKeyIsCorrectSize(t *testing.T) {
	p := software.New()
	resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(resp.GetKeyMaterial()) != mldsa65.PrivateKeySize {
		t.Errorf("private key size: got %d want %d", len(resp.GetKeyMaterial()), mldsa65.PrivateKeySize)
	}
}

func TestGenerateKey_MLDSA65_keysAreUnique(t *testing.T) {
	p := software.New()
	ctx := context.Background()

	r1, _ := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: mlDSA65Details()})
	r2, _ := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: mlDSA65Details()})

	if string(r1.GetPublicKeyBytes()) == string(r2.GetPublicKeyBytes()) {
		t.Error("two generated ML-DSA keys should not be identical")
	}
}

// mlDSAUnspecifiedParameterSetDetails returns an AlgorithmDetails with the
// ML-DSA parameter set left at its zero value. Unlike a specific-but-
// unimplemented parameter set (ML-DSA-44 was this placeholder before ML-DSA
// was generalized to 44/65/87 — see the analogous fix for ECDSA's
// unsupported-curve and Ed25519's unsupported-algorithm tests), UNSPECIFIED
// is not itself an algorithm and so can never become "supported": there is
// no scheme to dispatch to, only ever a caller error.
func mlDSAUnspecifiedParameterSetDetails() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_MlDsa{
			MlDsa: &types.MlDsaParams{
				ParameterSet: types.MlDsaParameterSet_ML_DSA_PARAMETER_SET_UNSPECIFIED,
			},
		},
	}
}

func TestGenerateKey_MLDSA_unspecifiedParameterSet_returnsError(t *testing.T) {
	p := software.New()
	_, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: mlDSAUnspecifiedParameterSetDetails(),
	})
	if err == nil {
		t.Fatal("expected error for unspecified ML-DSA parameter set on GenerateKey")
	}
}

func TestSign_MLDSA_unspecifiedParameterSet_returnsError(t *testing.T) {
	p, keyMaterial := genMLDSAKey(t)
	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("data"),
		Algorithm:   mlDSAUnspecifiedParameterSetDetails(),
	})
	if err == nil {
		t.Fatal("expected error for unspecified ML-DSA parameter set on Sign")
	}
}

func TestVerify_MLDSA_unspecifiedParameterSet_returnsError(t *testing.T) {
	p, keyMaterial := genMLDSAKey(t)
	signResult, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("data"),
		Algorithm:   mlDSA65Details(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_, err = p.Verify(context.Background(), &providerpb.VerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Input:       []byte("data"),
		Signature:   signResult.GetSignature(),
		Algorithm:   mlDSAUnspecifiedParameterSetDetails(),
	})
	if err == nil {
		t.Fatal("expected error for unspecified ML-DSA parameter set on Verify")
	}
}
