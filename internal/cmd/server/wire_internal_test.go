package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
)

// catalogPath returns the absolute path to standard_algorithms.json.
func catalogPath() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "..", "proto", "standard_algorithms.json")
}

// activatingFIPSConfig writes a wrapper config that .includes this
// machine's fipsmodule.cnf and activates the fips provider -- the same
// helper internal/provider/openssl's fips_test.go uses (duplicated here,
// not imported, since that one is unexported in a different package).
// Skips the test if fipsmodule.cnf is absent -- the FIPS module is an
// optional, separately-installed artifact.
func activatingFIPSConfig(t *testing.T) string {
	t.Helper()

	moduleConfig := ossl.DefaultFIPSModuleConfig()
	if _, err := os.Stat(moduleConfig); err != nil {
		t.Skipf("FIPS module config not present at %s (openssl fipsinstall not run on this machine): %v", moduleConfig, err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "fips_activate.cnf")
	content := fmt.Sprintf(`openssl_conf = openssl_init

.include %s

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
fips = fips_sect

[default_sect]
activate = 1
`, moduleConfig)

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing FIPS activation config: %v", err)
	}
	return path
}

// TestBuildProviderRegistry_registersBothProviders
// buildProviderRegistry registers both the software and
// openssl providers, not just software. Match's
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

	providerReg, err := buildProviderRegistry(ctx, templateReg, "")
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

// TestBuildProviderRegistry_FIPSConfigured_registersThirdProvider proves
// : an "openssl-fips" instance is registered when FIPSConfigPath is set,
// its context is genuinely FIPS-restricted (a strictly smaller advertised
// algorithm set than the default "openssl" instance -- ChaCha20-Poly1305 is
// not FIPS-approved and must be absent), and a key created via that FIPS
// instance round-trips sign/verify through it.
func TestBuildProviderRegistry_FIPSConfigured_registersThirdProvider(t *testing.T) {
	fipsCfgPath := activatingFIPSConfig(t)

	ctx := context.Background()
	templateReg, err := buildTemplateRegistry(ctx, &logical.InmemStorage{}, catalogPath())
	if err != nil {
		t.Fatalf("buildTemplateRegistry: %v", err)
	}

	providerReg, err := buildProviderRegistry(ctx, templateReg, fipsCfgPath)
	if err != nil {
		t.Fatalf("buildProviderRegistry: %v", err)
	}

	var names []string
	for _, p := range providerReg.List(ctx) {
		names = append(names, p.Name())
	}
	sort.Strings(names)
	want := []string{"openssl", "openssl-fips", "software"}
	if len(names) != len(want) {
		t.Fatalf("registered providers: got %v want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("registered providers: got %v want %v", names, want)
		}
	}

	baseProv, err := providerReg.Get(ctx, "openssl")
	if err != nil {
		t.Fatalf("Get(openssl): %v", err)
	}
	fipsProv, err := providerReg.Get(ctx, "openssl-fips")
	if err != nil {
		t.Fatalf("Get(openssl-fips): %v", err)
	}

	baseCap, ok := baseProv.(interface{ SupportedAlgorithms() []string })
	if !ok {
		t.Fatal("openssl provider does not implement SupportedAlgorithms")
	}
	fipsCap, ok := fipsProv.(interface{ SupportedAlgorithms() []string })
	if !ok {
		t.Fatal("openssl-fips provider does not implement SupportedAlgorithms")
	}
	baseAlgs, fipsAlgs := baseCap.SupportedAlgorithms(), fipsCap.SupportedAlgorithms()
	if len(fipsAlgs) >= len(baseAlgs) {
		t.Errorf("openssl-fips advertises %d algorithms, openssl advertises %d -- want strictly fewer under FIPS",
			len(fipsAlgs), len(baseAlgs))
	}
	for _, alg := range fipsAlgs {
		if alg == "chacha20-poly1305" {
			t.Error("openssl-fips advertises chacha20-poly1305, which is not FIPS-approved")
		}
	}

	// A key created via the FIPS instance genuinely round-trips sign/verify
	// through it -- not just that the instance exists and reports a
	// plausible-looking algorithm list.
	signer, ok := fipsProv.(provider.Signer)
	if !ok {
		t.Fatal("openssl-fips provider does not implement provider.Signer")
	}
	alg := &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_Ecdsa{
			Ecdsa: &types.EcdsaParams{Curve: types.EllipticCurve_ELLIPTIC_CURVE_P256},
		},
	}
	keyResp, err := fipsProv.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("openssl-fips GenerateKey: %v", err)
	}
	message := []byte("signed and verified through the FIPS instance")
	signResp, err := signer.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           alg,
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               message,
		ScopeParams:         &providerpb.SignRequest_NoContext{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("openssl-fips Sign: %v", err)
	}
	verifyResp, err := signer.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           alg,
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               message,
		Signature:           signResp.GetSignature(),
		ScopeParams:         &providerpb.VerifyRequest_NoContext{NoContext: &types.NoParams{}},
	})
	if err != nil {
		t.Fatalf("openssl-fips Verify: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("openssl-fips rejected a signature it produced itself")
	}
}

// TestBuildProviderRegistry_FIPSConstructionFails_isNonFatal proves the
// core requirement of registerFIPSProvider's design: a FIPSConfigPath that
// fails to construct (bad path, missing fipsmodule.cnf) does not abort
// server startup or poison the other two providers -- only the FIPS
// instance is skipped.
func TestBuildProviderRegistry_FIPSConstructionFails_isNonFatal(t *testing.T) {
	ctx := context.Background()
	templateReg, err := buildTemplateRegistry(ctx, &logical.InmemStorage{}, catalogPath())
	if err != nil {
		t.Fatalf("buildTemplateRegistry: %v", err)
	}

	providerReg, err := buildProviderRegistry(ctx, templateReg, "/nonexistent/path/that/does/not/exist.cnf")
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
		t.Fatalf("registered providers: got %v want %v (FIPS registration should have been skipped, not fatal)", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("registered providers: got %v want %v", names, want)
			break
		}
	}
}
