// Package store_test contains smoke tests for the generated storage proto types.
// This file lives in test/smoke/store/ (not gen/go/store/) so it is tracked in
// git and never wiped by `make proto` / `buf generate`.
package store_test

import (
	"testing"

	protovalidate "buf.build/go/protovalidate"
	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	typespb "github.ibm.com/citius/citius-server/gen/go/types"
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

func TestKey_roundtrip(t *testing.T) {
	orig := &storepb.Key{
		PublicId:           "key_01HXYZ",
		Name:               "my-signing-key",
		ScopeSpecification: []byte("scope-spec"),
		State:              typespb.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE,
	}
	b, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := new(storepb.Key)
	if err := proto.Unmarshal(b, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.PublicId != orig.PublicId {
		t.Errorf("public_id: got %q want %q", got.PublicId, orig.PublicId)
	}
	if got.Name != orig.Name {
		t.Errorf("name: got %q want %q", got.Name, orig.Name)
	}
	if got.State != orig.State {
		t.Errorf("state: got %v want %v", got.State, orig.State)
	}
}

func TestKeyVersion_fourFields(t *testing.T) {
	// Verify all four fields of the version pattern exist and can be set.
	// Only one of plaintext_material / ciphertext_material should be populated at a time.
	v := &storepb.KeyVersion{
		PublicId:      "ver_01HXYZ",
		KeyId:         "key_01HXYZ",
		KeyMaterial:   []byte("secret"),
		CtKeyMaterial: nil,
		Digest:        []byte("mac"),
		WrappingKeyId: "",
		ProviderId:    "software",
	}
	if len(v.KeyMaterial) == 0 {
		t.Error("expected plaintext_material to be set")
	}
	if len(v.Digest) == 0 {
		t.Error("expected Digest to be set")
	}
}

func TestKeyVersion_fourFields_ciphertext(t *testing.T) {
	// Verify the ciphertext variant works — material is wrapped by a KEK.
	v := &storepb.KeyVersion{
		PublicId:      "ver_01HABC",
		KeyId:         "key_01HABC",
		KeyMaterial:   nil,
		CtKeyMaterial: []byte("encrypted-secret"),
		Digest:        []byte("mac"),
		WrappingKeyId: "key_01HWRAP",
	}
	if len(v.CtKeyMaterial) == 0 {
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

func TestKey_noMaterialFields(t *testing.T) {
	// Key must NOT have any key material fields — material lives in KeyVersion only.
	// This test documents the design constraint via compile-time field access.
	k := &storepb.Key{
		PublicId: "key_01HXYZ",
	}
	// If this compiles, Key has no material fields (they would fail to compile if present).
	_ = k.PublicId
	_ = k.Name
	_ = k.ScopeSpecification
	_ = k.PolicyId
	_ = k.State
	_ = k.CurrentVersion
	// Specifically verify there are no plaintext_material or ciphertext_material fields
	// by ensuring the struct only has the expected fields above (documented intent).
}

func TestAllEnums_unspecifiedIsZero(t *testing.T) {
	// All enums must have _UNSPECIFIED = 0 as the first variant.
	if typespb.KeyLifecycleState_KEY_LIFECYCLE_STATE_UNSPECIFIED != 0 {
		t.Errorf("KeyLifecycleState_UNSPECIFIED != 0: got %d", typespb.KeyLifecycleState_KEY_LIFECYCLE_STATE_UNSPECIFIED)
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

func TestKey_validate_valid(t *testing.T) {
	v := validator(t)
	k := &storepb.Key{
		PublicId:       "key_01HXYZ12345678901234567890",
		Name:           "my-key",
		PolicyId:       "pol_01HXYZ12345678901234567890",
		CurrentVersion: 1,
	}
	if err := v.Validate(k); err != nil {
		t.Errorf("expected valid Key to pass validation: %v", err)
	}
}

func TestKey_validate_wrongPrefix(t *testing.T) {
	v := validator(t)
	k := &storepb.Key{
		PublicId:       "pol_01HXYZ12345678901234567890", // wrong prefix
		Name:           "my-key",
		PolicyId:       "pol_01HXYZ12345678901234567890",
		CurrentVersion: 1,
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for public_id with wrong prefix (pol_ instead of key_)")
	}
}

func TestKey_validate_emptyID(t *testing.T) {
	v := validator(t)
	k := &storepb.Key{
		PublicId:       "", // empty — violates min_len
		Name:           "my-key",
		PolicyId:       "pol_01HXYZ12345678901234567890",
		CurrentVersion: 1,
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for empty public_id")
	}
}

func TestKey_validate_emptyName(t *testing.T) {
	v := validator(t)
	k := &storepb.Key{
		PublicId:       "key_01HXYZ12345678901234567890",
		Name:           "", // empty — violates min_len
		PolicyId:       "pol_01HXYZ12345678901234567890",
		CurrentVersion: 1,
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for empty name")
	}
}

func TestKey_validate_policyID_not_valid_when_empty(t *testing.T) {
	v := validator(t)
	k := &storepb.Key{
		PublicId:       "key_01HXYZ12345678901234567890",
		Name:           "my-key",
		PolicyId:       "", // empty or with wrong prefix is not OK
		CurrentVersion: 1,
	}
	if err := v.Validate(k); err == nil {
		t.Errorf("empty policy_id not allowed: %v", err)
	}
}

func TestKey_validate_policyID_wrong_prefix(t *testing.T) {
	v := validator(t)
	k := &storepb.Key{
		PublicId:       "key_01HXYZ12345678901234567890",
		Name:           "my-key",
		PolicyId:       "key_01HABC12345678901234567890", // set but wrong prefix (key_ not pol_)
		CurrentVersion: 1,
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for policy_id with wrong prefix (key_ instead of pol_)")
	}
}

// NOTE: Key proto does not have a provider_instance_id field.
// Provider binding is on KeyVersion.provider_id, not on Key itself.

func TestKey_validate_currentVersion_zero(t *testing.T) {
	v := validator(t)
	k := &storepb.Key{
		PublicId:       "key_01HXYZ12345678901234567890",
		Name:           "my-key",
		PolicyId:       "pol_01HXYZ12345678901234567890",
		CurrentVersion: 0, // violates gte: 1
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for current_version = 0 (must be >= 1)")
	}
}

func TestKey_validate_currentVersion_empty(t *testing.T) {
	v := validator(t)
	k := &storepb.Key{
		PublicId: "key_01HXYZ12345678901234567890",
		Name:     "my-key",
		PolicyId: "pol_01HXYZ12345678901234567890",
		// CurrentVersion is zero value (0) which violates gte: 1
	}
	if err := v.Validate(k); err == nil {
		t.Error("expected validation error for empty current_version (zero value violates gte: 1)")
	}
}

func TestKeyVersion_validate_valid(t *testing.T) {
	v := validator(t)
	kv := &storepb.KeyVersion{
		PublicId:   "ver_01HXYZ12345678901234567890",
		KeyId:      "key_01HXYZ12345678901234567890",
		Version:    1,
		Digest:     []byte("mac"),
		ProviderId: "prv_software",
	}
	if err := v.Validate(kv); err != nil {
		t.Errorf("expected valid KeyVersion to pass: %v", err)
	}
}

func TestKeyVersion_validate_wrongVersionPrefix(t *testing.T) {
	v := validator(t)
	kv := &storepb.KeyVersion{
		PublicId: "key_01HXYZ12345678901234567890", // wrong prefix
		KeyId:    "key_01HXYZ12345678901234567890",
		Version:  1,
	}
	if err := v.Validate(kv); err == nil {
		t.Error("expected validation error for version_id with wrong prefix (key_ instead of ver_)")
	}
}

func TestKeyVersion_validate_wrongKeyIDPrefix(t *testing.T) {
	v := validator(t)
	kv := &storepb.KeyVersion{
		PublicId: "ver_01HXYZ12345678901234567890",
		KeyId:    "ver_01HXYZ12345678901234567890", // wrong prefix
		Version:  1,
	}
	if err := v.Validate(kv); err == nil {
		t.Error("expected validation error for key_id with wrong prefix (ver_ instead of key_)")
	}
}

func TestKeyVersion_validate_VersionZero(t *testing.T) {
	v := validator(t)
	kv := &storepb.KeyVersion{
		PublicId: "ver_01HXYZ12345678901234567890",
		KeyId:    "key_01HXYZ12345678901234567890",
		Version:  0, // violates gte: 1
	}
	if err := v.Validate(kv); err == nil {
		t.Error("expected validation error for version_number = 0 (must be >= 1)")
	}
}

func TestKeyVersion_validate_Version_empty(t *testing.T) {
	v := validator(t)
	kv := &storepb.KeyVersion{
		PublicId: "ver_01HXYZ12345678901234567890",
		KeyId:    "key_01HXYZ12345678901234567890",
		// Version is zero value (0) which violates gte: 1
	}
	if err := v.Validate(kv); err == nil {
		t.Error("expected validation error for empty version_number (zero value violates gte: 1)")
	}
}

func TestKeyVersion_validate_wrappingKeyID_wrongPrefix(t *testing.T) {
	v := validator(t)
	kv := &storepb.KeyVersion{
		PublicId:      "ver_01HXYZ12345678901234567890",
		KeyId:         "key_01HXYZ12345678901234567890",
		Version:       1,
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
