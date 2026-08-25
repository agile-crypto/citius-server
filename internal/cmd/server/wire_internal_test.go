package server

import (
	"context"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// catalogPath returns the absolute path to standard_algorithms.json.
func catalogPath() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "..", "proto", "standard_algorithms.json")
}

// TestBuildProviderRegistry_registersBothProviders proves C18's whole
// purpose directly: buildProviderRegistry registers both the software and
// openssl providers, not just software. MatchForTemplate's
// registration-order-first-match behavior means the existing
// TestSmoke_CreateKey_Sign_Verify (server_test package) alone would not
// catch openssl silently failing to register -- software, registered
// first, already satisfies every template openssl also supports, so no
// black-box request would ever observe openssl missing.
func TestBuildProviderRegistry_registersBothProviders(t *testing.T) {
	ctx := context.Background()
	templateReg, err := buildTemplateRegistry(ctx, &logical.InmemStorage{}, catalogPath())
	if err != nil {
		t.Fatalf("buildTemplateRegistry: %v", err)
	}

	providerReg, err := buildProviderRegistry(ctx, templateReg)
	if err != nil {
		t.Fatalf("buildProviderRegistry: %v", err)
	}

	var names []string
	for _, p := range providerReg.List(ctx) {
		names = append(names, p.Name())
	}
	sort.Strings(names)

	want := []string{"openssl", "software"}
	if len(names) != len(want) {
		t.Fatalf("registered providers: got %v want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("registered providers: got %v want %v", names, want)
			break
		}
	}
}
