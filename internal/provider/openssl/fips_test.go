package openssl_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/agile-crypto/ossl-go/ossl"

	"github.com/agile-crypto/citius-server/internal/provider/openssl"
)

// activatingFIPSConfig writes a wrapper config that .includes this
// machine's fipsmodule.cnf (written by `openssl fipsinstall`) and activates
// the fips provider — the shape WithFIPS's doc comment documents as
// required. ossl.DefaultFIPSModuleConfig alone is not a valid configPath: it
// has no openssl_conf directive and cannot be loaded on its own.
//
// Skips the test if fipsmodule.cnf is absent — the FIPS module is an
// optional, separately-installed artifact, not something every environment
// running this suite is expected to have.
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

func TestNew_withFIPS_activatesFIPS(t *testing.T) {
	cfgPath := activatingFIPSConfig(t)

	p, err := openssl.New(context.Background(), openssl.WithName("openssl-fips"), openssl.WithFIPS(cfgPath))
	if err != nil {
		t.Fatalf("openssl.New with WithFIPS: %v", err)
	}
	defer p.Close()

	if !p.FIPSEnabled() {
		t.Error("FIPSEnabled: got false, want true for a WithFIPS instance")
	}
}

func TestNew_withFIPS_reportsFIPSApproved(t *testing.T) {
	cfgPath := activatingFIPSConfig(t)

	p, err := openssl.New(context.Background(), openssl.WithName("openssl-fips"), openssl.WithFIPS(cfgPath))
	if err != nil {
		t.Fatalf("openssl.New with WithFIPS: %v", err)
	}
	defer p.Close()

	fips := p.ImplementationProperties().GetFips_140()
	if fips == nil {
		t.Fatal("Fips_140: got nil, want non-nil for a WithFIPS instance")
	}
	if !fips.GetCertified() {
		t.Error("Fips_140.Certified: got false, want true")
	}
}

func TestNew_withoutFIPS_notEnabled(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	if p.FIPSEnabled() {
		t.Error("FIPSEnabled: got true, want false for a default-mode instance")
	}
}

// TestNew_withFIPS_nonexistentConfig_errorsCleanly is the negative control
// for WithFIPS's error path.
//
// It deliberately covers only a config path that fails at OSSL_LIB_CTX's
// own config-loading step (file not found), never reaching
// OSSL_PROVIDER_load("fips"). Verified by hand — not committed as a test,
// for the reason explained below — that a config which reaches
// OSSL_PROVIDER_load and fails there (e.g. syntactically valid but missing
// the fipsmodule.cnf include) poisons the FIPS module process-wide and
// permanently: every later FIPS activation in the same process fails too,
// even a correct config in a brand-new context. Exercising that path here
// would break every other FIPS test in this package's test binary depending
// on run order. See WithFIPS's doc comment.
func TestNew_withFIPS_nonexistentConfig_errorsCleanly(t *testing.T) {
	p, err := openssl.New(context.Background(), openssl.WithFIPS("/nonexistent/path/that/does/not/exist.cnf"))
	if err == nil {
		p.Close()
		t.Fatal("expected an error for a nonexistent FIPS config path, got nil")
	}
}
