package crypto_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"testing"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-server/internal/cmd/server"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const aeadTemplate = "aes-256-gcm-128-96"

func aeadScope() *typespb.ScopeSpecification {
	return &typespb.ScopeSpecification{ScopeSpec: &typespb.ScopeSpecification_Aead{
		Aead: &typespb.AeadScopeSpec{Scope: typespb.AeadScope_AEAD_SCOPE_STANDARD},
	}}
}

func signatureScope(scope typespb.SignatureScope, security *typespb.UniversalSecurityProperties) *typespb.ScopeSpecification {
	return &typespb.ScopeSpecification{ScopeSpec: &typespb.ScopeSpecification_Signature{
		Signature: &typespb.SignatureScopeSpec{Scope: scope, Security: security},
	}}
}

// providerRulePolicy returns the rules of a policy allowing templates and
// operations, with an optional provider_requirements section.
func providerRulePolicy(t *testing.T, templates, operations []string, providerRequirements map[string]any) string {
	t.Helper()
	rules := map[string]any{
		"version":            "1",
		"allowed_templates":  templates,
		"allowed_operations": map[string]any{"key_operations": operations},
	}
	if providerRequirements != nil {
		rules["provider_requirements"] = providerRequirements
	}
	b, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal policy rules: %v", err)
	}
	return string(b)
}

// TestSmoke_CreateKey_providerRequirementsChooseTheProvider proves the
// provider_requirements of a CreateKey request choose among the software
// (memory-safe, registered first) and openssl (hardware-accelerated)
// instances, and that a pin contradicting a requirement is refused.
func TestSmoke_CreateKey_providerRequirementsChooseTheProvider(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	pol := seedPolicy(t, ctx, h, "aead", []string{aeadTemplate}, []string{"create_key"})

	tests := []struct {
		name         string
		pin          string
		requirements *typespb.ProviderRequirements
		wantProvider string
		wantCode     codes.Code
	}{
		{name: "none: registration order", wantProvider: "software"},
		{name: "memory safe", requirements: &typespb.ProviderRequirements{MemorySafe: proto.Bool(true)}, wantProvider: "software"},
		{name: "prefer hardware acceleration", requirements: &typespb.ProviderRequirements{PreferHardwareAccelerated: proto.Bool(true)}, wantProvider: "openssl"},
		{name: "FIPS 140 without a FIPS instance", requirements: &typespb.ProviderRequirements{Fips_140Certified: proto.Bool(true)}, wantCode: codes.NotFound},
		{name: "pin contradicts a requirement", pin: "openssl", requirements: &typespb.ProviderRequirements{MemorySafe: proto.Bool(true)}, wantCode: codes.FailedPrecondition},
		{name: "unenforceable requirement", requirements: &typespb.ProviderRequirements{Additional: map[string]string{"vendor": "acme"}}, wantCode: codes.InvalidArgument},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tid := aeadTemplate
			resp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
				Name:                 fmt.Sprintf("key-%d", i),
				Policy:               pol,
				TemplateId:           &tid,
				ScopeSpec:            aeadScope(),
				ProviderId:           tt.pin,
				ProviderRequirements: tt.requirements,
			})
			if tt.wantCode != codes.OK {
				if got := status.Code(err); got != tt.wantCode {
					t.Fatalf("CreateKey: code = %s, want %s (err %v)", got, tt.wantCode, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateKey: %v", err)
			}
			if got := resp.GetKeyMetadata().GetProvider(); got != tt.wantProvider {
				t.Errorf("CreateKey: provider = %q, want %q", got, tt.wantProvider)
			}
		})
	}
}

// TestSmoke_CreateKey_scopeFIPSApprovalSelectsAlgorithmsOnly records
// decision DT-027: fips_approved in a scope selects a FIPS-approved
// algorithm (ML-DSA, FIPS 204) and does not force a FIPS 140 certified
// provider, so the pinned software provider serves it.
func TestSmoke_CreateKey_scopeFIPSApprovalSelectsAlgorithmsOnly(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	pol := seedPolicy(t, ctx, h, "pqc", []string{"ml-dsa-65"}, []string{"create_key"})

	tid := "ml-dsa-65"
	resp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name:       "pqc-key",
		Policy:     pol,
		TemplateId: &tid,
		ProviderId: "software",
		ScopeSpec: signatureScope(typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD,
			&typespb.UniversalSecurityProperties{FipsApproved: proto.Bool(true), QuantumSafe: proto.Bool(true)}),
		ProviderRequirements: &typespb.ProviderRequirements{MemorySafe: proto.Bool(true)},
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if got := resp.GetKeyMetadata().GetProvider(); got != "software" {
		t.Errorf("CreateKey: provider = %q, want software", got)
	}
}

// TestSmoke_CreateKey_intentBasedProviderRequirements proves provider
// requirements apply to intent-based creation (a scope and no template or
// pin): the template comes from the policy's list, the provider from the
// requirements. A preference never skips a template the policy lists first,
// and a requirement no instance meets leaves no template to select.
func TestSmoke_CreateKey_intentBasedProviderRequirements(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	// ecdsa-p256-prehashed-der is implemented by software only.
	pol := seedPolicy(t, ctx, h, "intent",
		[]string{"ecdsa-p256-prehashed-der", "ed25519ph", aeadTemplate}, []string{"create_key"})
	prehashed := signatureScope(typespb.SignatureScope_SIGNATURE_SCOPE_PREHASHED, nil)

	tests := []struct {
		name         string
		scope        *typespb.ScopeSpecification
		requirements *typespb.ProviderRequirements
		want         string // template@provider
		wantCode     codes.Code
	}{
		{name: "memory safe", scope: prehashed,
			requirements: &typespb.ProviderRequirements{MemorySafe: proto.Bool(true)}, want: "ecdsa-p256-prehashed-der@software"},
		{name: "a preference does not skip a template", scope: prehashed,
			requirements: &typespb.ProviderRequirements{PreferHardwareAccelerated: proto.Bool(true)}, want: "ecdsa-p256-prehashed-der@software"},
		{name: "prefer hardware acceleration", scope: aeadScope(),
			requirements: &typespb.ProviderRequirements{PreferHardwareAccelerated: proto.Bool(true)}, want: aeadTemplate + "@openssl"},
		{name: "FIPS 140 without a FIPS instance", scope: aeadScope(),
			requirements: &typespb.ProviderRequirements{Fips_140Certified: proto.Bool(true)}, wantCode: codes.NotFound},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
				Name: fmt.Sprintf("intent-key-%d", i), Policy: pol, ScopeSpec: tt.scope, ProviderRequirements: tt.requirements,
			})
			if tt.wantCode != codes.OK {
				if got := status.Code(err); got != tt.wantCode {
					t.Fatalf("CreateKey: code = %s, want %s (err %v)", got, tt.wantCode, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateKey: %v", err)
			}
			md := resp.GetKeyMetadata()
			if got := md.GetTemplateId() + "@" + md.GetProvider(); got != tt.want {
				t.Errorf("CreateKey: %s, want %s", got, tt.want)
			}
		})
	}
}

// TestSmoke_CreateKey_fipsInstance_scopeFIPSApprovalDoesNotChooseIt
// records decision DT-027 with a FIPS instance registered: a scope's
// fips_approved selects algorithms, so with no provider requirement the
// first registered instance (software) serves the key; only a FIPS 140
// provider requirement selects openssl-fips. Skips without a FIPS module.
func TestSmoke_CreateKey_fipsInstance_scopeFIPSApprovalDoesNotChooseIt(t *testing.T) {
	ctx := context.Background()
	h, err := server.NewTestableServer(ctx, server.Config{
		CatalogPath:    catalogPath(),
		FIPSConfigPath: activatingFIPSConfig(t),
	})
	if err != nil {
		t.Fatalf("NewTestableServer: %v", err)
	}
	pol := seedPolicy(t, ctx, h, "fips-scope", []string{aeadTemplate}, []string{"create_key"})
	fipsApproved := &typespb.ScopeSpecification{ScopeSpec: &typespb.ScopeSpecification_Aead{
		Aead: &typespb.AeadScopeSpec{
			Scope:    typespb.AeadScope_AEAD_SCOPE_STANDARD,
			Security: &typespb.UniversalSecurityProperties{FipsApproved: proto.Bool(true)},
		},
	}}

	for i, tt := range []struct {
		requirements *typespb.ProviderRequirements
		want         string
	}{
		{nil, "software"},
		{&typespb.ProviderRequirements{Fips_140Certified: proto.Bool(true)}, "openssl-fips"},
	} {
		resp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
			Name: fmt.Sprintf("fips-scope-key-%d", i), Policy: pol, ScopeSpec: fipsApproved, ProviderRequirements: tt.requirements,
		})
		if err != nil {
			t.Fatalf("CreateKey (requirements %v): %v", tt.requirements, err)
		}
		if got := resp.GetKeyMetadata().GetProvider(); got != tt.want {
			t.Errorf("CreateKey (requirements %v): provider = %q, want %q", tt.requirements, got, tt.want)
		}
	}
}

// TestSmoke_PolicyProviderRequirements_governTheKeyLifecycle proves a
// policy's provider_requirements rule (DT-029) applies to every key under
// the policy, whenever a version is placed on a provider: a key on openssl
// can no longer be transformed in place once the policy requires a
// memory-safe provider, may migrate to software, and may not migrate back.
func TestSmoke_PolicyProviderRequirements_governTheKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	ops := []string{"create_key", "read_key", "encrypt", "decrypt"}
	pol := seedPolicy(t, ctx, h, "governed", []string{aeadTemplate}, ops)

	tid := aeadTemplate
	if _, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name: "governed-key", Policy: pol, TemplateId: &tid, ScopeSpec: aeadScope(), ProviderId: "openssl",
	}); err != nil {
		t.Fatalf("CreateKey on openssl: %v", err)
	}
	enc, err := h.CryptoHandler.Encrypt(ctx, &messagespb.EncryptRequest{
		KeyName: "governed-key", Plaintext: []byte("before the rule"),
		ScopeParams: &messagespb.EncryptRequest_AeadParams{AeadParams: &typespb.AeadEncryptParams{}},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err = h.PolicyHandler.UpdateCryptoPolicy(ctx, &messagespb.UpdateCryptoPolicyRequest{
		Name:           pol,
		PolicyDocument: providerRulePolicy(t, []string{aeadTemplate}, ops, map[string]any{"memory_safe": true}),
		Format:         "json",
	}); err != nil {
		t.Fatalf("UpdateCryptoPolicy: %v", err)
	}

	if _, err = h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
		Name: "refused-key", Policy: pol, TemplateId: &tid, ScopeSpec: aeadScope(), ProviderId: "openssl",
	}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("CreateKey on openssl under the rule: code = %s, want FailedPrecondition", status.Code(err))
	}
	if _, err = h.KeysHandler.TransformKey(ctx, &messagespb.TransformKeyRequest{
		Name: "governed-key", TemplateId: &tid, ScopeSpec: aeadScope(),
	}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("TransformKey on openssl under the rule: code = %s, want FailedPrecondition", status.Code(err))
	}

	migrate := func(target string) error {
		_, mErr := h.KeysHandler.MigrateKey(ctx, &messagespb.MigrateKeyRequest{
			Name:     "governed-key",
			Target:   &messagespb.MigrateKeyRequest_TargetInstanceId{TargetInstanceId: target},
			Strategy: messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
		})
		return mErr
	}
	if err = migrate("software"); err != nil {
		t.Fatalf("MigrateKey to software: %v", err)
	}
	if err = migrate("openssl"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("MigrateKey back to openssl: code = %s, want FailedPrecondition", status.Code(err))
	}

	dec, err := h.CryptoHandler.Decrypt(ctx, &messagespb.DecryptRequest{
		KeyName: "governed-key", Ciphertext: enc.GetCiphertext(), Metadata: enc.GetMetadata(),
		ScopeParams: &messagespb.DecryptRequest_AeadParams{AeadParams: &typespb.AeadEncryptParams{}},
	})
	if err != nil || string(dec.GetPlaintext()) != "before the rule" {
		t.Errorf("Decrypt after migration: %q, %v", dec.GetPlaintext(), err)
	}
}

// catalogTemplateIDs returns every template ID in the catalog, in order.
func catalogTemplateIDs(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(catalogPath())
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	var ids []string
	for _, m := range regexp.MustCompile(`"templateId":\s*"([^"]+)"`).FindAllStringSubmatch(string(b), -1) {
		if !slices.Contains(ids, m[1]) {
			ids = append(ids, m[1])
		}
	}
	return ids
}

// TestSmoke_CreateKey_wholeCatalogPolicy_selectsServableTemplates proves
// intent-based creation under a policy allowing the whole catalog (DT-026):
// templates listed before a servable one but implemented by no provider
// (hybrids) or not by the pinned provider are skipped, not selected and
// then refused. The expected templates are the first servable ones in
// catalog order.
func TestSmoke_CreateKey_wholeCatalogPolicy_selectsServableTemplates(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	pol := seedPolicy(t, ctx, h, "catalog", catalogTemplateIDs(t), []string{"create_key"})
	quantumSafe := &typespb.UniversalSecurityProperties{QuantumSafe: proto.Bool(true)}

	tests := []struct {
		name  string
		pin   string
		scope *typespb.ScopeSpecification
		want  string // template@provider
	}{
		{"signature", "", signatureScope(typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD, nil), "ml-dsa-44@software"},
		{"quantum-safe signature", "", signatureScope(typespb.SignatureScope_SIGNATURE_SCOPE_STANDARD, quantumSafe), "ml-dsa-44@software"},
		{"prehashed signature", "", signatureScope(typespb.SignatureScope_SIGNATURE_SCOPE_PREHASHED, nil), "ed25519ph@software"},
		{"prehashed signature on openssl", "openssl", signatureScope(typespb.SignatureScope_SIGNATURE_SCOPE_PREHASHED, nil), "ed25519ph@openssl"},
		{"AEAD", "", aeadScope(), "aes-128-gcm-128-96@software"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := h.KeysHandler.CreateKey(ctx, &messagespb.CreateKeyRequest{
				Name: fmt.Sprintf("catalog-key-%d", i), Policy: pol, ScopeSpec: tt.scope, ProviderId: tt.pin,
			})
			if err != nil {
				t.Fatalf("CreateKey: %v", err)
			}
			md := resp.GetKeyMetadata()
			if got := md.GetTemplateId() + "@" + md.GetProvider(); got != tt.want {
				t.Errorf("CreateKey: %s, want %s", got, tt.want)
			}
		})
	}
}
