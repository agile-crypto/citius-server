package provider_test

import (
	"context"
	"fmt"
	"testing"

	metapb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	provider "github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
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

	// ECDSA-P256 is supported by every registered provider today, and
	// supports all four Signer methods uniformly (unlike ML-DSA and pure
	// Ed25519, which reject SignDigest/VerifyDigest outright since they are
	// not prehashable — see additionalSignVerifyOnlyAlgorithms below), so it
	// is the one algorithm exercised through the full Sign/Verify/
	// SignDigest/VerifyDigest surface.
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
	if ok {
		assertSignerAlwaysSetsOutput(t, ctx, signer, algo, genResp)

		// Beyond ECDSA: cover the other algorithm families this provider
		// implements (RSA-PSS, RSA-PKCS1v15, Ed25519, ML-DSA-44/65/87) via
		// Sign/Verify — the two methods every signature algorithm supports
		// uniformly — so a future algorithm branch that forgets to call
		// NoOutput/NoOutputUnencoded is caught regardless of which family it
		// belongs to, not just for ECDSA-P256.
		for _, sampleAlgo := range additionalSignVerifyOnlyAlgorithms() {
			t.Run(algorithmLabel(sampleAlgo), func(t *testing.T) {
				sampleGenResp, genErr := backend.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: sampleAlgo})
				if genErr != nil {
					t.Fatalf("GenerateKey: %v", genErr)
				}
				requireAlgorithmOutput(t, "GenerateKey", sampleGenResp.GetOutput())
				assertSignVerifyAlwaysSetsOutput(t, ctx, signer, sampleAlgo, sampleGenResp)
			})
		}
	}

	cipher, ok := backend.(provider.Cipher)
	if !ok {
		return
	}

	// Cipher needs its own algorithm-appropriate key: ECDSA is a signature
	// algorithm, and a real Cipher implementation correctly rejects it for
	// Encrypt/Decrypt — unlike loopback's algorithm-agnostic echo, which
	// never validated this and let ECDSA slip through unnoticed here.
	cipherAlgo := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_AesGcm{
			AesGcm: &types.AesGcmParams{KeySizeBits: 256, IvSizeBits: 96, TagSizeBits: 128},
		},
	}
	cipherGenResp, err := backend.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: cipherAlgo})
	if err != nil {
		t.Fatalf("GenerateKey (cipher): %v", err)
	}
	requireAlgorithmOutput(t, "GenerateKey (cipher)", cipherGenResp.GetOutput())

	assertCipherAlwaysSetsOutput(t, ctx, cipher, cipherAlgo, cipherGenResp)
}

// assertSignVerifyAlwaysSetsOutput checks only Sign/Verify — the two
// methods every signature algorithm in this provider supports, unlike
// SignDigest/VerifyDigest which ML-DSA and pure Ed25519 reject outright
// (not prehashable). Extracted from assertSignerAlwaysSetsOutput so the
// additional-algorithm loop in assertBackendAlwaysSetsOutput can reuse it
// without needing to know which algorithms support prehashing.
func assertSignVerifyAlwaysSetsOutput(t *testing.T, ctx context.Context, signer provider.Signer, algo *types.AlgorithmDetails, genResp *providerpb.GenerateKeyResponse) {
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
}

// additionalSignVerifyOnlyAlgorithms returns one representative
// AlgorithmDetails per signature family beyond ECDSA (RSA-PSS,
// RSA-PKCS1v15, Ed25519, ML-DSA-44/65/87) — enough to catch a missing
// NoOutput/NoOutputUnencoded call in any family's Sign/Verify dispatch arm,
// without needing every parameter-set variant.
func additionalSignVerifyOnlyAlgorithms() []*types.AlgorithmDetails {
	return []*types.AlgorithmDetails{
		{Algorithm: &types.AlgorithmDetails_RsaPss{
			RsaPss: &types.RsaPssParams{KeySizeBits: 2048, Hash: types.HashAlgorithm_HASH_ALGORITHM_SHA256},
		}},
		{Algorithm: &types.AlgorithmDetails_RsaPkcs1V15{
			RsaPkcs1V15: &types.RsaPkcs1V15Params{KeySizeBits: 2048, Hash: types.HashAlgorithm_HASH_ALGORITHM_SHA256},
		}},
		{Algorithm: &types.AlgorithmDetails_Ed25519{
			Ed25519: &types.Ed25519Params{Variant: types.Ed25519Variant_ED25519_VARIANT_PURE},
		}},
		{Algorithm: &types.AlgorithmDetails_MlDsa{
			MlDsa: &types.MlDsaParams{ParameterSet: types.MlDsaParameterSet_ML_DSA_44},
		}},
		{Algorithm: &types.AlgorithmDetails_MlDsa{
			MlDsa: &types.MlDsaParams{ParameterSet: types.MlDsaParameterSet_ML_DSA_65},
		}},
		{Algorithm: &types.AlgorithmDetails_MlDsa{
			MlDsa: &types.MlDsaParams{ParameterSet: types.MlDsaParameterSet_ML_DSA_87},
		}},
	}
}

// algorithmLabel names a subtest after the AlgorithmDetails oneof arm's
// concrete type, so a failure points at exactly which algorithm family
// regressed (e.g. "*types.AlgorithmDetails_RsaPss") without needing a
// separate label per entry in additionalSignVerifyOnlyAlgorithms.
func algorithmLabel(algo *types.AlgorithmDetails) string {
	return fmt.Sprintf("%T", algo.GetAlgorithm())
}

func assertSignerAlwaysSetsOutput(t *testing.T, ctx context.Context, signer provider.Signer, algo *types.AlgorithmDetails, genResp *providerpb.GenerateKeyResponse) {
	t.Helper()

	assertSignVerifyAlwaysSetsOutput(t, ctx, signer, algo, genResp)

	// hash_algorithm is left unset — this test exercises the ProviderOutput
	// contract, not digest-length validation, so any digest length works.
	digest := []byte("arbitrary-length-pre-hashed-digest")

	digestSignResp, err := signer.SignDigest(ctx, &providerpb.SignDigestRequest{
		KeyMaterial: genResp.GetKeyMaterial(),
		Digest:      digest,
		Algorithm:   algo,
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	requireAlgorithmOutput(t, "SignDigest", digestSignResp.GetOutput())

	digestVerifyResp, err := signer.VerifyDigest(ctx, &providerpb.VerifyDigestRequest{
		KeyMaterial: genResp.GetPublicKeyBytes(),
		Digest:      digest,
		Signature:   digestSignResp.GetSignature(),
		Algorithm:   algo,
	})
	if err != nil {
		t.Fatalf("VerifyDigest: %v", err)
	}
	requireAlgorithmOutput(t, "VerifyDigest", digestVerifyResp.GetOutput())
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
