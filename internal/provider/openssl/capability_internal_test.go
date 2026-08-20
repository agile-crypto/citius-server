// This file is in package openssl rather than openssl_test — deriveAlgorithms
// and catalog are unexported, and testing them directly here is what makes it
// possible to inject a synthetic table independent of the real (currently
// empty) catalog this package advertises, proving the filtering mechanism
// itself is correct before any real algorithm's capability lands in it.
package openssl

import (
	"testing"

	"github.com/agile-crypto/ossl-go/ossl"
)

// TestDeriveAlgorithms_filtersUnsupported is the negative control the plan
// calls for: a capability the context genuinely lacks must not appear in the
// result. "BOGUS-KEY-ALGORITHM" is not a real ossl-go/OpenSSL key name, so
// ossl.Context.Supports rejects it the same way it would reject any
// algorithm a differently-configured context (FIPS, a narrower provider set)
// genuinely does not have — this is not a tautological "the list equals the
// table" check.
func TestDeriveAlgorithms_filtersUnsupported(t *testing.T) {
	libctx, err := ossl.NewContext()
	if err != nil {
		t.Fatalf("ossl.NewContext: %v", err)
	}
	defer libctx.Close()

	table := map[string]ossl.Capability{
		"test-supported":   ossl.SignatureCapability{Key: ossl.Ed25519},
		"test-unsupported": ossl.SignatureCapability{Key: "BOGUS-KEY-ALGORITHM"},
	}

	got := deriveAlgorithms(libctx, table)

	if len(got) != 1 || got[0] != "test-supported" {
		t.Errorf("deriveAlgorithms: got %v, want exactly [test-supported]", got)
	}
}

// TestDeriveAlgorithms_emptyTable proves an empty table (the package's real
// catalog today, before any algorithm's full path lands) derives an empty
// result rather than panicking or returning something non-empty.
func TestDeriveAlgorithms_emptyTable(t *testing.T) {
	libctx, err := ossl.NewContext()
	if err != nil {
		t.Fatalf("ossl.NewContext: %v", err)
	}
	defer libctx.Close()

	got := deriveAlgorithms(libctx, map[string]ossl.Capability{})
	if len(got) != 0 {
		t.Errorf("deriveAlgorithms(empty table): got %v, want empty", got)
	}
}

// TestDeriveAlgorithms_sortedOutput proves the result is sorted regardless
// of the table's (randomized) map iteration order — a caller comparing
// SupportedAlgorithms output, or a test asserting equality, should not have
// to tolerate nondeterministic ordering.
func TestDeriveAlgorithms_sortedOutput(t *testing.T) {
	libctx, err := ossl.NewContext()
	if err != nil {
		t.Fatalf("ossl.NewContext: %v", err)
	}
	defer libctx.Close()

	table := map[string]ossl.Capability{
		"zzz-last":   ossl.SignatureCapability{Key: ossl.Ed25519},
		"aaa-first":  ossl.SignatureCapability{Key: ossl.Ed25519},
		"mmm-middle": ossl.SignatureCapability{Key: ossl.Ed25519},
	}

	got := deriveAlgorithms(libctx, table)

	want := []string{"aaa-first", "mmm-middle", "zzz-last"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q want %q (full: got=%v want=%v)", i, got[i], want[i], got, want)
		}
	}
}
