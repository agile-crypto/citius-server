package software_test

import (
	"context"
	"crypto/sha256"
	"testing"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
)

// ============================================================================
// DigestSign / DigestVerify — Digest Length Validation
// ============================================================================

func TestDigestSign_wrongDigestLength_returnsInvalidArgument(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)

	// A 20-byte digest cannot have come from SHA-256 (32 bytes).
	_, err := p.DigestSign(context.Background(), &providerpb.DigestSignRequest{
		KeyMaterial:   keyMaterial.GetKeyMaterial(),
		Digest:        make([]byte, 20),
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Algorithm:     ecdsaP256Details(),
	})
	if err == nil {
		t.Fatal("expected error for digest length mismatch")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestDigestVerify_wrongDigestLength_returnsInvalidArgument(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)

	_, err := p.DigestVerify(context.Background(), &providerpb.DigestVerifyRequest{
		KeyMaterial:   keyMaterial.GetPublicKeyBytes(),
		Digest:        make([]byte, 20),
		Signature:     []byte("fake-sig"),
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Algorithm:     ecdsaP256Details(),
	})
	if err == nil {
		t.Fatal("expected error for digest length mismatch")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestDigestSign_correctDigestLengthForDeclaredHash_succeeds(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	digest := sha256.Sum256([]byte("payload"))

	_, err := p.DigestSign(context.Background(), &providerpb.DigestSignRequest{
		KeyMaterial:   keyMaterial.GetKeyMaterial(),
		Digest:        digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA256,
		Algorithm:     ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("DigestSign: %v", err)
	}
}

func TestDigestSign_sha384LengthMismatch_returnsInvalidArgument(t *testing.T) {
	p, keyMaterial := genECDSAKey(t)
	digest := sha256.Sum256([]byte("payload")) // 32 bytes — wrong for SHA-384 (48 bytes)

	_, err := p.DigestSign(context.Background(), &providerpb.DigestSignRequest{
		KeyMaterial:   keyMaterial.GetKeyMaterial(),
		Digest:        digest[:],
		HashAlgorithm: types.HashAlgorithm_HASH_ALGORITHM_SHA384,
		Algorithm:     ecdsaP256Details(),
	})
	if err == nil {
		t.Fatal("expected error for digest length mismatch")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument, got: %v", err)
	}
}

func TestDigestSign_unspecifiedHashAlgorithm_skipsLengthCheck(t *testing.T) {
	// HASH_ALGORITHM_UNSPECIFIED (the zero value) has no fixed length, so any
	// digest length is accepted — this is what keeps the dispatch tests in
	// digest_sign_test.go (which don't declare a hash) passing.
	p, keyMaterial := genECDSAKey(t)

	_, err := p.DigestSign(context.Background(), &providerpb.DigestSignRequest{
		KeyMaterial: keyMaterial.GetKeyMaterial(),
		Digest:      make([]byte, 20),
		Algorithm:   ecdsaP256Details(),
	})
	if err != nil {
		t.Fatalf("DigestSign with unspecified hash_algorithm should not fail length validation: %v", err)
	}
}
