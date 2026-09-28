package crypto_test

import (
	"context"
	"testing"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	"github.com/agile-crypto/citius-server/internal/cmd/server"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestSmoke_ValidateKeyOperation_migrate asks, without side effects, how a
// software key can move to openssl: both in-process providers carry the
// stored payload, so PROVIDER_SWITCH is recommended; the strategies no
// provider supports say why not.
func TestSmoke_ValidateKeyOperation_migrate(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	pol := seedPolicy(t, ctx, h, "validate-migrate", []string{aeadTemplate}, []string{"create_key", "read_key"})
	keyName := createAEADKey(t, ctx, h, "validate-migrate-key", pol)

	resp, err := h.KeysHandler.ValidateKeyOperation(ctx, &messagespb.ValidateKeyOperationRequest{
		Name: keyName,
		Intent: &messagespb.ValidateKeyOperationRequest_Migrate{Migrate: &messagespb.ValidateMigrateIntent{
			Target: &messagespb.ValidateMigrateIntent_TargetInstanceId{TargetInstanceId: "openssl"},
		}},
	})
	if err != nil {
		t.Fatalf("ValidateKeyOperation: %v", err)
	}
	if st := resp.GetCurrentState(); st.GetInstanceId() != "software" || !st.GetExtractable() || st.GetTemplateId() != aeadTemplate {
		t.Errorf("current state = %v, want an extractable %s key on software", st, aeadTemplate)
	}
	want := map[messagespb.MigrationStrategy]bool{
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH:    true,
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT: false,
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_WRAPPED_TRANSFER:   false,
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE:  true,
		messagespb.MigrationStrategy_MIGRATION_STRATEGY_REKEY_AND_DESTROY:  false,
	}
	if len(resp.GetOptions()) != len(want) {
		t.Fatalf("options = %v, want one per strategy", resp.GetOptions())
	}
	for _, o := range resp.GetOptions() {
		if o.GetFeasible() != want[o.GetStrategy()] {
			t.Errorf("%s: feasible = %v (%s), want %v", o.GetStrategy(), o.GetFeasible(), o.GetInfeasibilityReason(), want[o.GetStrategy()])
		}
		if !o.GetFeasible() && o.GetInfeasibilityReason() == "" {
			t.Errorf("%s: infeasible with no reason", o.GetStrategy())
		}
	}
	if got := resp.GetRecommendedStrategy(); got != messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH {
		t.Errorf("recommended = %s, want PROVIDER_SWITCH", got)
	}

	read, err := h.KeysHandler.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: keyName})
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if md := read.GetKeyMetadata(); md.GetVersion() != 1 || md.GetProvider() != "software" {
		t.Errorf("after validation the key is at %s v%d, want software v1", md.GetProvider(), md.GetVersion())
	}
}

// TestSmoke_MigrateKey_ProviderSwitch_keepsExtractability reads the
// extractability each version records: generated on software, the material
// may leave it, and it still may once switched to openssl.
func TestSmoke_MigrateKey_ProviderSwitch_keepsExtractability(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	pol := seedPolicy(t, ctx, h, "extractable", []string{aeadTemplate}, []string{"create_key", "read_key"})
	keyName := createAEADKey(t, ctx, h, "extractable-key", pol)

	extractable := func() bool {
		t.Helper()
		read, err := h.KeysHandler.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: keyName})
		if err != nil {
			t.Fatalf("ReadKey: %v", err)
		}
		return read.GetKeyMetadata().GetExtractable()
	}
	if !extractable() {
		t.Error("a software key must be recorded extractable")
	}
	if _, err := h.KeysHandler.MigrateKey(ctx, &messagespb.MigrateKeyRequest{
		Name:     keyName,
		Target:   &messagespb.MigrateKeyRequest_TargetInstanceId{TargetInstanceId: "openssl"},
		Strategy: messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
	}); err != nil {
		t.Fatalf("MigrateKey: %v", err)
	}
	if !extractable() {
		t.Error("a key switched to openssl must stay extractable")
	}
}

// TestSmoke_CreateKey_approvedGenerationNeedsAValidatedModule proves a
// policy's approved_generation rule refuses keys no FIPS 140 validated
// module generates.
func TestSmoke_CreateKey_approvedGenerationNeedsAValidatedModule(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	pol := approvedGenerationPolicy(t, ctx, h, "approved-generation")

	tid := aeadTemplate
	for _, tt := range []struct {
		pin  string
		want codes.Code
	}{
		{"", codes.NotFound},                   // no instance qualifies
		{"software", codes.FailedPrecondition}, // the pinned instance does not
	} {
		_, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
			Name: "approved-" + tt.pin, Policy: pol, TemplateId: &tid, ScopeSpec: aeadScope(), ProviderId: tt.pin,
		})
		if code := status.Code(err); code != tt.want {
			t.Errorf("CreateKey (pin %q) under approved_generation without a FIPS instance: code = %s, want %s", tt.pin, code, tt.want)
		}
	}
}

// TestSmoke_KeyTransfer_FIPSInstance walks a key through the FIPS instance
// with and without an approved lineage. Skips without a FIPS module.
//
//   - A key generated on openssl-fips is extractable, since the module is
//     at level 1, but under a fips_140_certified policy may not switch to
//     software.
//   - A key generated on software may switch into openssl-fips, but its
//     material then has no approved lineage: once the policy requires
//     approved generation, a transform may not retain it, whereas it may
//     retain the material of a key generated on openssl-fips.
func TestSmoke_KeyTransfer_FIPSInstance(t *testing.T) {
	ctx := context.Background()
	h, err := server.NewTestableServer(ctx, server.Config{
		CatalogPath:    catalogPath(),
		FIPSConfigPath: activatingFIPSConfig(t),
	})
	if err != nil {
		t.Fatalf("NewTestableServer: %v", err)
	}
	ops := []string{"create_key", "read_key"}
	tid := aeadTemplate
	switchTo := func(keyName, target string) error {
		_, mErr := h.KeysHandler.MigrateKey(ctx, &messagespb.MigrateKeyRequest{
			Name:     keyName,
			Target:   &messagespb.MigrateKeyRequest_TargetInstanceId{TargetInstanceId: target},
			Strategy: messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
		})
		return mErr
	}

	fipsPol := seedPolicy(t, ctx, h, "fips-held", []string{aeadTemplate}, ops)
	if _, err = h.PolicyHandler.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name: fipsPol, Format: "json",
		PolicyDocument: providerRulePolicy(t, []string{aeadTemplate}, ops, map[string]any{"fips_140_certified": true}),
	}); err != nil {
		t.Fatalf("UpdateCryptoPolicy: %v", err)
	}
	if _, err = h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name: "fips-held-key", Policy: fipsPol, TemplateId: &tid, ScopeSpec: aeadScope(),
	}); err != nil {
		t.Fatalf("CreateKey under fips_140_certified: %v", err)
	}
	read, err := h.KeysHandler.ReadKey(ctx, &messagespb.ReadKeyRequest{Name: "fips-held-key"})
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if md := read.GetKeyMetadata(); md.GetProvider() != "openssl-fips" || !md.GetExtractable() {
		t.Errorf("fips-held-key on %q, extractable %v; want an extractable key on openssl-fips", md.GetProvider(), md.GetExtractable())
	}
	if err = switchTo("fips-held-key", "software"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("MigrateKey openssl-fips -> software under fips_140_certified: code = %s, want FailedPrecondition", status.Code(err))
	}

	pol := seedPolicy(t, ctx, h, "switched-in", []string{aeadTemplate}, ops)
	if _, err = h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name: "switched-in-key", Policy: pol, TemplateId: &tid, ScopeSpec: aeadScope(), ProviderId: "software",
	}); err != nil {
		t.Fatalf("CreateKey on software: %v", err)
	}
	if err = switchTo("switched-in-key", "openssl-fips"); err != nil {
		t.Fatalf("MigrateKey software -> openssl-fips: %v", err)
	}
	if _, err = h.PolicyHandler.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name: pol, Format: "json",
		PolicyDocument: providerRulePolicy(t, []string{aeadTemplate}, ops, map[string]any{"approved_generation": true}),
	}); err != nil {
		t.Fatalf("UpdateCryptoPolicy: %v", err)
	}
	retain := func(keyName string) error {
		_, tErr := h.KeysHandler.TransformKey(ctx, &messagespb.TransformKeyRequest{
			Name: keyName, TemplateId: &tid, ScopeSpec: aeadScope(), RetainKeyBytes: true,
		})
		return tErr
	}
	if err = retain("switched-in-key"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("TransformKey retaining material without an approved lineage: code = %s, want FailedPrecondition", status.Code(err))
	}
	if _, err = h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name: "approved-key", Policy: pol, TemplateId: &tid, ScopeSpec: aeadScope(),
	}); err != nil {
		t.Fatalf("CreateKey under approved_generation: %v", err)
	}
	if err = retain("approved-key"); err != nil {
		t.Errorf("TransformKey retaining material with an approved lineage: %v", err)
	}
}

// approvedGenerationPolicy seeds a policy for the AEAD template whose
// provider_requirements rule requires approved generation.
func approvedGenerationPolicy(t *testing.T, ctx context.Context, h *server.TestableHandler, name string) string {
	t.Helper()
	ops := []string{"create_key"}
	pol := seedPolicy(t, ctx, h, name, []string{aeadTemplate}, ops)
	if _, err := h.PolicyHandler.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name: pol, Format: "json",
		PolicyDocument: providerRulePolicy(t, []string{aeadTemplate}, ops, map[string]any{"approved_generation": true}),
	}); err != nil {
		t.Fatalf("UpdateCryptoPolicy: %v", err)
	}
	return pol
}
