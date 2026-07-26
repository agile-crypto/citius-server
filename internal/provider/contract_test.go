package provider_test

import (
	"context"
	"testing"

	metapb "github.com/agile-crypto/citius-server/gen/go/api/messages"
	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/provider"
	"github.com/agile-crypto/citius-server/internal/provider/loopback"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

// TestBackends_alwaysSetProviderOutput is the Phase 0 closing gate: every
// provider.Backend / provider.Signer / provider.Cipher implementation MUST
// set ProviderOutput.algorithm_output on every successful response —
// metadata.proto states an unset oneof means the provider forgot to set it,
// and the core MUST reject the response (enforced at the orchestrator layer
// by requireProviderOutput).
//
// This test exercises every capability method on every registered provider
// and fails loudly if a future algorithm branch or a new provider forgets to
// call NoOutput / NoOutputUnencoded — closing exactly the gap that let 9 of
// 11 provider return sites ship without Output originally.
func TestBackends_alwaysSetProviderOutput(t *testing.T) {
	backends := []provider.Backend{
		software.New(),
		loopback.New(),
	}

	for _, backend := range backends {
		t.Run(backend.Name(), func(t *testing.T) {
			assertBackendAlwaysSetsOutput(t, backend)
		})
	}
}

func assertBackendAlwaysSetsOutput(t *testing.T, backend provider.Backend) {
	t.Helper()
	ctx := context.Background()

	// ECDSA-P256 is supported by every registered provider today.
	algo := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{
				Curve: types.EllipticCurve_ELLIPTIC_CURVE_P256,
				Hash:  types.HashAlgorithm_HASH_ALGORITHM_SHA256,
			},
		},
	}

	genResp, err := backend.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: algo})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	requireAlgorithmOutput(t, "GenerateKey", genResp.GetOutput())

	signer, ok := backend.(provider.Signer)
	if !ok {
		return
	}
	assertSignerAlwaysSetsOutput(t, ctx, signer, algo, genResp)

	cipher, ok := backend.(provider.Cipher)
	if !ok {
		return
	}
	assertCipherAlwaysSetsOutput(t, ctx, cipher, algo, genResp)
}

func assertSignerAlwaysSetsOutput(t *testing.T, ctx context.Context, signer provider.Signer, algo *types.AlgorithmDetails, genResp *providerpb.GenerateKeyResponse) {
	t.Helper()

	signResp, err := signer.Sign(ctx, &providerpb.SignRequest{
		KeyMaterial: genResp.GetKeyMaterial(),
		Input:       []byte("payload"),
		Algorithm:   algo,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	requireAlgorithmOutput(t, "Sign", signResp.GetOutput())

	verifyResp, err := signer.Verify(ctx, &providerpb.VerifyRequest{
		KeyMaterial: genResp.GetPublicKeyBytes(),
		Input:       []byte("payload"),
		Signature:   signResp.GetSignature(),
		Algorithm:   algo,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	requireAlgorithmOutput(t, "Verify", verifyResp.GetOutput())

	// hash_algorithm is left unset — this test exercises the ProviderOutput
	// contract, not digest-length validation, so any digest length works.
	digest := []byte("arbitrary-length-pre-hashed-digest")

	digestSignResp, err := signer.DigestSign(ctx, &providerpb.DigestSignRequest{
		KeyMaterial: genResp.GetKeyMaterial(),
		Digest:      digest,
		Algorithm:   algo,
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}
	requireAlgorithmOutput(t, "DigestSign", digestSignResp.GetOutput())

	digestVerifyResp, err := signer.DigestVerify(ctx, &providerpb.DigestVerifyRequest{
		KeyMaterial: genResp.GetPublicKeyBytes(),
		Digest:      digest,
		Signature:   digestSignResp.GetSignature(),
		Algorithm:   algo,
	})
	if err != nil {
		t.Fatalf("DigestVerify: %v", err)
	}
	requireAlgorithmOutput(t, "DigestVerify", digestVerifyResp.GetOutput())
}

func assertCipherAlwaysSetsOutput(t *testing.T, ctx context.Context, cipher provider.Cipher, algo *types.AlgorithmDetails, genResp *providerpb.GenerateKeyResponse) {
	t.Helper()

	encResp, err := cipher.Encrypt(ctx, &providerpb.EncryptRequest{
		KeyMaterial: genResp.GetKeyMaterial(),
		Plaintext:   []byte("secret"),
		Algorithm:   algo,
		ScopeParams: &providerpb.EncryptRequest_NoParams{NoParams: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	requireAlgorithmOutput(t, "Encrypt", encResp.GetOutput())

	decResp, err := cipher.Decrypt(ctx, &providerpb.DecryptRequest{
		KeyMaterial: genResp.GetKeyMaterial(),
		Ciphertext:  encResp.GetCiphertext(),
		Algorithm:   algo,
		Output:      encResp.GetOutput(),
		ScopeParams: &providerpb.DecryptRequest_NoParams{NoParams: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	requireAlgorithmOutput(t, "Decrypt", decResp.GetOutput())
}

func requireAlgorithmOutput(t *testing.T, method string, out *metapb.ProviderOutput) {
	t.Helper()
	if out.GetAlgorithmOutput() == nil {
		t.Errorf("%s: algorithm_output is nil — provider must call provider.NoOutput or provider.NoOutputUnencoded", method)
	}
}
