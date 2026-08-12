package software_test

import (
	"context"
	"crypto/sha256"
	"testing"

	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

// ============================================================================
// DigestSign / DigestVerify — AlgorithmDetails Dispatch
// ============================================================================

func TestDigestSign_ECDSA_P256_happyPath(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	digest := sha256.Sum256([]byte("pre-hashed by the caller"))

	result, err := p.DigestSign(context.Background(), &providerpb.DigestSignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Digest:      digest[:],
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}
	if len(result.GetSignature()) == 0 {
		t.Error("expected non-empty signature")
	}
}

func TestDigestSign_DigestVerify_roundtrip(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	ctx := context.Background()
	digest := sha256.Sum256([]byte("round-trip payload"))

	signResult, err := p.DigestSign(ctx, &providerpb.DigestSignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Digest:      digest[:],
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}

	verifyResult, err := p.DigestVerify(ctx, &providerpb.DigestVerifyRequest{
		KeyMaterial: keyMaterial.GetPublicKeyBytes(),
		Digest:      digest[:],
		Signature:   signResult.GetSignature(),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("DigestVerify: %v", err)
	}
	if !verifyResult.GetValid() {
		t.Error("expected valid=true for a correctly round-tripped digest signature")
	}
}

func TestDigestSign_MLDSA_returnsInvalidArgument(t *testing.T) {
	// Pure ML-DSA is not prehashable — DigestSign must reject it with a
	// specific, explanatory error, not the generic "unsupported type" message
	// a truly unrecognized algorithm would get.
	_, err := software.New().DigestSign(context.Background(), &providerpb.DigestSignRequest{
		KeyMaterial: []byte("fake-key"),
		Digest:      []byte("fake-digest"),
		Algorithm:   mlDSA65Details(),
	})
	if err == nil {
		t.Fatal("expected error for ML-DSA DigestSign")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestDigestVerify_MLDSA_returnsInvalidArgument(t *testing.T) {
	_, err := software.New().DigestVerify(context.Background(), &providerpb.DigestVerifyRequest{
		KeyMaterial: []byte("fake-key"),
		Digest:      []byte("fake-digest"),
		Signature:   []byte("fake-sig"),
		Algorithm:   mlDSA65Details(),
	})
	if err == nil {
		t.Fatal("expected error for ML-DSA DigestVerify")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestDigestSign_unsetAlgorithm_returnsNotImplemented(t *testing.T) {
	_, err := software.New().DigestSign(context.Background(), &providerpb.DigestSignRequest{
		KeyMaterial: []byte("fake-key"),
		Digest:      []byte("fake-digest"),
	})
	if err == nil {
		t.Fatal("expected error for unset algorithm")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}

func TestDigestVerify_unsetAlgorithm_returnsNotImplemented(t *testing.T) {
	_, err := software.New().DigestVerify(context.Background(), &providerpb.DigestVerifyRequest{
		KeyMaterial: []byte("fake-key"),
		Digest:      []byte("fake-digest"),
		Signature:   []byte("fake-sig"),
	})
	if err == nil {
		t.Fatal("expected error for unset algorithm")
	}
	if !errors.IsNotImplemented(err) {
		t.Errorf("expected CodeNotImplemented, got: %v", err)
	}
}
