package software_test

import (
	"context"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
	types "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/provider/software"
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

// mlDSA44Details returns an AlgorithmDetails for ML-DSA-44 (unsupported).
func mlDSA44Details() *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_MlDsa{
			MlDsa: &types.MlDsaParams{
				ParameterSet: types.MlDsaParameterSet_ML_DSA_44,
			},
		},
	}
}

func TestGenerateKey_MLDSA_unsupportedParameterSet_returnsError(t *testing.T) {
	p := software.New()
	_, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{
		Algorithm: mlDSA44Details(),
	})
	if err == nil {
		t.Fatal("expected error for unsupported ML-DSA-44 parameter set on GenerateKey")
	}
}

func TestSign_MLDSA_unsupportedParameterSet_returnsError(t *testing.T) {
	p, keyMaterial := genMLDSAKey(t)
	_, err := p.Sign(context.Background(), &providerpb.SignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Input:       []byte("data"),
		Algorithm:   mlDSA44Details(),
	})
	if err == nil {
		t.Fatal("expected error for unsupported ML-DSA-44 parameter set on Sign")
	}
}

func TestVerify_MLDSA_unsupportedParameterSet_returnsError(t *testing.T) {
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
		Algorithm:   mlDSA44Details(),
	})
	if err == nil {
		t.Fatal("expected error for unsupported ML-DSA-44 parameter set on Verify")
	}
}
