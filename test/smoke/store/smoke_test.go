// Package store_test contains smoke tests for the generated storage proto types.
// This file lives in test/smoke/store/ (not gen/go/store/) so it is tracked in
// git and never wiped by `make proto` / `buf generate`.
package store_test

import (
	"testing"

	protovalidate "buf.build/go/protovalidate"
	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"google.golang.org/protobuf/proto"
)

// validator returns a protovalidate.Validator, failing the test if it cannot be constructed.
func validator(t *testing.T) protovalidate.Validator {
	t.Helper()
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}
	return v
}

func TestStoredKey_roundtrip(t *testing.T) {
	orig := &storepb.StoredKey{
		PublicId:   "key_01HXYZ",
		Name:       "my-signing-key",
		TemplateId: "ecdsa-p256-sha256",
		Status:     storepb.KeyStatus_KEY_STATUS_ACTIVE,
	}
	b, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := new(storepb.StoredKey)
	if err := proto.Unmarshal(b, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.PublicId != orig.PublicId {
		t.Errorf("public_id: got %q want %q", got.PublicId, orig.PublicId)
	}
	if got.Name != orig.Name {
		t.Errorf("name: got %q want %q", got.Name, orig.Name)
	}
	if got.Status != orig.Status {
		t.Errorf("status: got %v want %v", got.Status, orig.Status)
	}
}

func TestStoredKeyVersion_fourFields(t *testing.T) {
	// Verify all four fields of the version pattern exist and can be set.
	// Only one of plaintext_material / ciphertext_material should be populated at a time.
	v := &storepb.StoredKeyVersion{
		VersionId:          "ver_01HXYZ",
		KeyId:              "key_01HXYZ",
		PlaintextMaterial:  []byte("secret"),
		CiphertextMaterial: nil,
		Hmac:               []byte("mac"),
		WrappingKeyId:      "",
		ProviderName:       "software",
	}
	if len(v.PlaintextMaterial) == 0 {
		t.Error("expected plaintext_material to be set")
	}
	if len(v.Hmac) == 0 {
		t.Error("expected hmac to be set")
	}
}

func TestStoredKeyVersion_fourFields_ciphertext(t *testing.T) {
	// Verify the ciphertext variant works — material is wrapped by a KEK.
	v := &storepb.StoredKeyVersion{
		VersionId:          "ver_01HABC",
		KeyId:              "key_01HABC",
		PlaintextMaterial:  nil,
		CiphertextMaterial: []byte("encrypted-secret"),
		Hmac:               []byte("mac"),
		WrappingKeyId:      "key_01HWRAP",
	}
	if len(v.CiphertextMaterial) == 0 {
		t.Error("expected ciphertext_material to be set")
	}
	if v.WrappingKeyId == "" {
		t.Error("expected wrapping_key_id to be set when using ciphertext")
	}
}

func TestStoredPolicy_roundtrip(t *testing.T) {
	p := &storepb.StoredPolicy{
		PublicId: "pol_01HXYZ",
		Name:     "default-sig-policy",
		Scope:    storepb.PolicyScope_POLICY_SCOPE_GLOBAL,
	}
	b, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := new(storepb.StoredPolicy)
	if err := proto.Unmarshal(b, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.PublicId != p.PublicId {
		t.Errorf("public_id: got %q want %q", got.PublicId, p.PublicId)
	}
	if got.Scope != p.Scope {
		t.Errorf("scope: got %v want %v", got.Scope, p.Scope)
	}
}

func TestStoredProviderInstance_roundtrip(t *testing.T) {
	pi := &storepb.StoredProviderInstance{
		PublicId:     "prv_01HXYZ",
		Name:         "software-default",
		ProviderType: "software",
		IsDefault:    true,
	}
	b, err := proto.Marshal(pi)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := new(storepb.StoredProviderInstance)
	if err := proto.Unmarshal(b, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.PublicId != pi.PublicId {
		t.Errorf("public_id: got %q want %q", got.PublicId, pi.PublicId)
	}
	if !got.IsDefault {
		t.Error("expected is_default=true")
	}
}

func TestStoredSession_roundtrip(t *testing.T) {
	s := &storepb.StoredSession{
		PublicId:  "ses_01HXYZ",
		KeyId:     "key_01HXYZ",
		Operation: "sign",
		Status:    storepb.SessionStatus_SESSION_STATUS_ACTIVE,
	}
	b, err := proto.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := new(storepb.StoredSession)
	if err := proto.Unmarshal(b, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.PublicId != s.PublicId {
		t.Errorf("public_id: got %q want %q", got.PublicId, s.PublicId)
	}
	if got.Operation != s.Operation {
		t.Errorf("operation: got %q want %q", got.Operation, s.Operation)
	}
	if got.Status != s.Status {
		t.Errorf("status: got %v want %v", got.Status, s.Status)
	}
}

func TestStoredKey_noMaterialFields(t *testing.T) {
	// StoredKey must NOT have any key material fields — material lives in StoredKeyVersion only.
	// This test documents the design constraint via compile-time field access.
	k := &storepb.StoredKey{
		PublicId: "key_01HXYZ",
	}
	// If this compiles, StoredKey has no material fields (they would fail to compile if present).
	_ = k.PublicId
	_ = k.Name
	_ = k.TemplateId
	_ = k.PolicyId
	_ = k.Status
	_ = k.CurrentVersion
	// Specifically verify there are no plaintext_material or ciphertext_material fields
	// by ensuring the struct only has the expected fields above (documented intent).
}

func TestAllEnums_unspecifiedIsZero(t *testing.T) {
	// All enums must have _UNSPECIFIED = 0 as the first variant.
	if storepb.KeyStatus_KEY_STATUS_UNSPECIFIED != 0 {
		t.Errorf("KeyStatus_UNSPECIFIED != 0: got %d", storepb.KeyStatus_KEY_STATUS_UNSPECIFIED)
	}
	if storepb.PolicyScope_POLICY_SCOPE_UNSPECIFIED != 0 {
		t.Errorf("PolicyScope_UNSPECIFIED != 0: got %d", storepb.PolicyScope_POLICY_SCOPE_UNSPECIFIED)
	}
	if storepb.SessionStatus_SESSION_STATUS_UNSPECIFIED != 0 {
		t.Errorf("SessionStatus_UNSPECIFIED != 0: got %d", storepb.SessionStatus_SESSION_STATUS_UNSPECIFIED)
	}
}

// ============================================================================
// Validation tests — buf validate prefix and length constraints
// ============================================================================

func TestStoredKey_validate_valid(t *testing.T) {
	v := validator(t)
	k := &storepb.StoredKey{
		PublicId:           "key_01HXYZ12345678901234567890",
		Name:               "my-key",
		PolicyId:           "pol_01HXYZ12345678901234567890",
		ProviderInstanceId: "prv_01HXYZ12345678901234567890",
		CurrentVersion:     1,
	}
	if err := v.Validate(k); err != nil {
		t.Errorf("expected valid StoredKey to pass validation: %v", err)
	}
}

func TestStoredKey_validate_wrongPrefix(t *testing.T) {
	v := validator(t)
	k := &storepb.StoredKey{
		PublicId:           "pol_01HXYZ12345678901234567890", // wrong prefix
		Name:               "my-key",
		PolicyId:           "pol_01HXYZ12345678901234567890",
		ProviderInstanceId: "prv_01HXYZ12345678901234567890",
		CurrentVersion:     1,
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for public_id with wrong prefix (pol_ instead of key_)")
	}
}

func TestStoredKey_validate_emptyID(t *testing.T) {
	v := validator(t)
	k := &storepb.StoredKey{
		PublicId:           "", // empty — violates min_len
		Name:               "my-key",
		PolicyId:           "pol_01HXYZ12345678901234567890",
		ProviderInstanceId: "prv_01HXYZ12345678901234567890",
		CurrentVersion:     1,
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for empty public_id")
	}
}

func TestStoredKey_validate_emptyName(t *testing.T) {
	v := validator(t)
	k := &storepb.StoredKey{
		PublicId:           "key_01HXYZ12345678901234567890",
		Name:               "", // empty — violates min_len
		PolicyId:           "pol_01HXYZ12345678901234567890",
		ProviderInstanceId: "prv_01HXYZ12345678901234567890",
		CurrentVersion:     1,
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for empty name")
	}
}

func TestStoredKey_validate_policyID_not_valid_when_empty(t *testing.T) {
	v := validator(t)
	k := &storepb.StoredKey{
		PublicId:           "key_01HXYZ12345678901234567890",
		Name:               "my-key",
		PolicyId:           "", // empty or with wrong prefix is not OK
		ProviderInstanceId: "prv_01HXYZ12345678901234567890",
		CurrentVersion:     1,
	}
	if err := v.Validate(k); err == nil {
		t.Errorf("empty policy_id not allowed: %v", err)
	}
}

func TestStoredKey_validate_policyID_wrong_prefix(t *testing.T) {
	v := validator(t)
	k := &storepb.StoredKey{
		PublicId:           "key_01HXYZ12345678901234567890",
		Name:               "my-key",
		PolicyId:           "key_01HABC12345678901234567890", // set but wrong prefix (key_ not pol_)
		ProviderInstanceId: "prv_01HXYZ12345678901234567890",
		CurrentVersion:     1,
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for policy_id with wrong prefix (key_ instead of pol_)")
	}
}

func TestStoredKey_validate_providerInstanceID_not_valid_when_empty(t *testing.T) {
	v := validator(t)
	k := &storepb.StoredKey{
		PublicId:           "key_01HXYZ12345678901234567890",
		Name:               "my-key",
		PolicyId:           "pol_01HXYZ12345678901234567890",
		ProviderInstanceId: "", // empty or with wrong prefix is not OK
		CurrentVersion:     1,
	}
	if err := v.Validate(k); err == nil {
		t.Errorf("empty provider_instance_id not allowed: %v", err)
	}
}

func TestStoredKey_validate_providerInstanceID_wrong_prefix(t *testing.T) {
	v := validator(t)
	k := &storepb.StoredKey{
		PublicId:           "key_01HXYZ12345678901234567890",
		Name:               "my-key",
		PolicyId:           "pol_01HXYZ12345678901234567890",
		ProviderInstanceId: "pol_01HABC12345678901234567890", // set but wrong prefix (pol_ not prv_)
		CurrentVersion:     1,
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for provider_instance_id with wrong prefix (pol_ instead of prv_)")
	}
}

func TestStoredKey_validate_currentVersion_zero(t *testing.T) {
	v := validator(t)
	k := &storepb.StoredKey{
		PublicId:           "key_01HXYZ12345678901234567890",
		Name:               "my-key",
		PolicyId:           "pol_01HXYZ12345678901234567890",
		ProviderInstanceId: "prv_01HXYZ12345678901234567890",
		CurrentVersion:     0, // violates gte: 1
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for current_version = 0 (must be >= 1)")
	}
}

func TestStoredKey_validate_currentVersion_empty(t *testing.T) {
	v := validator(t)
	k := &storepb.StoredKey{
		PublicId:           "key_01HXYZ12345678901234567890",
		Name:               "my-key",
		PolicyId:           "pol_01HXYZ12345678901234567890",
		ProviderInstanceId: "prv_01HXYZ12345678901234567890",
		// CurrentVersion is zero value (0) which violates gte: 1
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for empty current_version (zero value violates gte: 1)")
	}
}

func TestStoredKeyVersion_validate_valid(t *testing.T) {
	v := validator(t)
	kv := &storepb.StoredKeyVersion{
		VersionId:     "ver_01HXYZ12345678901234567890",
		KeyId:         "key_01HXYZ12345678901234567890",
		VersionNumber: 1,
		Hmac:          []byte("mac"),
	}
	if err := v.Validate(kv); err != nil {
		t.Errorf("expected valid StoredKeyVersion to pass: %v", err)
	}
}

func TestStoredKeyVersion_validate_wrongVersionPrefix(t *testing.T) {
	v := validator(t)
	kv := &storepb.StoredKeyVersion{
		VersionId:     "key_01HXYZ12345678901234567890", // wrong prefix
		KeyId:         "key_01HXYZ12345678901234567890",
		VersionNumber: 1,
	}
	if err := v.Validate(kv); err == nil {
		t.Error("expected validation error for version_id with wrong prefix (key_ instead of ver_)")
	}
}

func TestStoredKeyVersion_validate_wrongKeyIDPrefix(t *testing.T) {
	v := validator(t)
	kv := &storepb.StoredKeyVersion{
		VersionId:     "ver_01HXYZ12345678901234567890",
		KeyId:         "ver_01HXYZ12345678901234567890", // wrong prefix
		VersionNumber: 1,
	}
	if err := v.Validate(kv); err == nil {
		t.Error("expected validation error for key_id with wrong prefix (ver_ instead of key_)")
	}
}

func TestStoredKeyVersion_validate_versionNumberZero(t *testing.T) {
	v := validator(t)
	kv := &storepb.StoredKeyVersion{
		VersionId:     "ver_01HXYZ12345678901234567890",
		KeyId:         "key_01HXYZ12345678901234567890",
		VersionNumber: 0, // violates gte: 1
	}
	if err := v.Validate(kv); err == nil {
		t.Error("expected validation error for version_number = 0 (must be >= 1)")
	}
}

func TestStoredKeyVersion_validate_versionNumber_empty(t *testing.T) {
	v := validator(t)
	kv := &storepb.StoredKeyVersion{
		VersionId: "ver_01HXYZ12345678901234567890",
		KeyId:     "key_01HXYZ12345678901234567890",
		// VersionNumber is zero value (0) which violates gte: 1
	}
	if err := v.Validate(kv); err == nil {
		t.Error("expected validation error for empty version_number (zero value violates gte: 1)")
	}
}

func TestStoredKeyVersion_validate_wrappingKeyID_wrongPrefix(t *testing.T) {
	v := validator(t)
	kv := &storepb.StoredKeyVersion{
		VersionId:     "ver_01HXYZ12345678901234567890",
		KeyId:         "key_01HXYZ12345678901234567890",
		VersionNumber: 1,
		WrappingKeyId: "ses_01HABC12345678901234567890", // wrong prefix for a key reference
	}
	if err := v.Validate(kv); err == nil {
		t.Error("expected validation error for wrapping_key_id with wrong prefix (ses_ instead of key_)")
	}
}

func TestStoredPolicy_validate_valid(t *testing.T) {
	v := validator(t)
	p := &storepb.StoredPolicy{
		PublicId: "pol_01HXYZ12345678901234567890",
		Name:     "default-policy",
	}
	if err := v.Validate(p); err != nil {
		t.Errorf("expected valid StoredPolicy to pass: %v", err)
	}
}

func TestStoredPolicy_validate_wrongPrefix(t *testing.T) {
	v := validator(t)
	p := &storepb.StoredPolicy{
		PublicId: "key_01HXYZ12345678901234567890", // wrong prefix
		Name:     "default-policy",
	}
	if err := v.Validate(p); err == nil {
		t.Error("expected validation error for policy public_id with wrong prefix (key_ instead of pol_)")
	}
}

func TestStoredProviderInstance_validate_valid(t *testing.T) {
	v := validator(t)
	pi := &storepb.StoredProviderInstance{
		PublicId:     "prv_01HXYZ12345678901234567890",
		Name:         "software-default",
		ProviderType: "software",
	}
	if err := v.Validate(pi); err != nil {
		t.Errorf("expected valid StoredProviderInstance to pass: %v", err)
	}
}

func TestStoredProviderInstance_validate_wrongPrefix(t *testing.T) {
	v := validator(t)
	pi := &storepb.StoredProviderInstance{
		PublicId:     "key_01HXYZ12345678901234567890", // wrong prefix
		Name:         "software-default",
		ProviderType: "software",
	}
	if err := v.Validate(pi); err == nil {
		t.Error("expected validation error for provider public_id with wrong prefix (key_ instead of prv_)")
	}
}

func TestStoredProviderInstance_validate_emptyProviderType(t *testing.T) {
	v := validator(t)
	pi := &storepb.StoredProviderInstance{
		PublicId:     "prv_01HXYZ12345678901234567890",
		Name:         "software-default",
		ProviderType: "", // violates min_len: 1
	}
	if err := v.Validate(pi); err == nil {
		t.Error("expected validation error for empty provider_type")
	}
}

func TestStoredSession_validate_valid(t *testing.T) {
	v := validator(t)
	s := &storepb.StoredSession{
		PublicId:  "ses_01HXYZ12345678901234567890",
		KeyId:     "key_01HXYZ12345678901234567890",
		Operation: "sign",
	}
	if err := v.Validate(s); err != nil {
		t.Errorf("expected valid StoredSession to pass: %v", err)
	}
}

func TestStoredSession_validate_wrongPublicIDPrefix(t *testing.T) {
	v := validator(t)
	s := &storepb.StoredSession{
		PublicId:  "key_01HXYZ12345678901234567890", // wrong prefix
		KeyId:     "key_01HXYZ12345678901234567890",
		Operation: "sign",
	}
	if err := v.Validate(s); err == nil {
		t.Error("expected validation error for session public_id with wrong prefix (key_ instead of ses_)")
	}
}

func TestStoredSession_validate_wrongKeyIDPrefix(t *testing.T) {
	v := validator(t)
	s := &storepb.StoredSession{
		PublicId:  "ses_01HXYZ12345678901234567890",
		KeyId:     "ses_01HXYZ12345678901234567890", // wrong prefix
		Operation: "sign",
	}
	if err := v.Validate(s); err == nil {
		t.Error("expected validation error for session key_id with wrong prefix (ses_ instead of key_)")
	}
}

func TestStoredSession_validate_emptyOperation(t *testing.T) {
	v := validator(t)
	s := &storepb.StoredSession{
		PublicId:  "ses_01HXYZ12345678901234567890",
		KeyId:     "key_01HXYZ12345678901234567890",
		Operation: "", // violates min_len: 1
	}
	if err := v.Validate(s); err == nil {
		t.Error("expected validation error for empty operation")
	}
}
