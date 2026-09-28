// This file is in package openssl rather than openssl_test so that the
// properties a FIPS instance reports can be checked without a FIPS module:
// implementationProperties is unexported.
package openssl

import (
	"context"
	"testing"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
)

// fipsView is a default-mode instance reporting the properties of a FIPS
// one, for the core's transfer clamp to act on.
type fipsView struct{ *Provider }

func (fipsView) ImplementationProperties() *types.ImplementationProperties {
	return implementationProperties(true)
}

// TestFIPSInstance_keepsTheStoredPayloadChannel checks that what a FIPS
// instance reports lets the core switch keys onto and off it: at FIPS 140
// level 1 the core keeps the stored-payload channel open, where a
// certification with no level, or a higher one, would close it.
func TestFIPSInstance_keepsTheStoredPayloadChannel(t *testing.T) {
	if got := implementationProperties(false).GetFips_140(); got != nil {
		t.Fatalf("default mode reports FIPS 140 %v, want none", got)
	}
	fips := implementationProperties(true).GetFips_140()
	if !fips.GetCertified() || fips.GetLevel() != types.Fips140Level_FIPS_140_LEVEL_1 {
		t.Fatalf("FIPS mode reports %v, want certified at level 1", fips)
	}

	p, err := New(context.Background())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()
	alg := &types.AlgorithmDetails{Algorithm: &types.AlgorithmDetails_Ecdsa{
		Ecdsa: &types.EcdsaParams{Curve: types.EllipticCurve_ELLIPTIC_CURVE_P256},
	}}
	got := provider.TransferOf(fipsView{p}, alg)
	if len(got.Emit.StoredPayload) == 0 || len(got.Accept.StoredPayload) == 0 {
		t.Errorf("TransferOf a FIPS instance = %+v, want the stored-payload channel open", got)
	}
}
