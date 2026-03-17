package core

// Primitive identifies a cryptographic primitive family.
// Each Primitive maps 1:1 to a ScopeSpecification oneof field in common.proto.
type Primitive string

const (
	PrimitiveSignature       Primitive = "signature"
	PrimitiveAead            Primitive = "aead"
	PrimitiveMac             Primitive = "mac"
	PrimitiveKem             Primitive = "kem"
	PrimitiveKeyAgreement    Primitive = "key_agreement"
	PrimitiveKdf             Primitive = "kdf"
	PrimitiveHash            Primitive = "hash"
	PrimitiveKeyWrapping     Primitive = "key_wrapping"
	PrimitiveSymmetricCipher Primitive = "symmetric_cipher"
	PrimitiveGenericSecret   Primitive = "generic_secret"
)

// Scope identifies a specific operational variant within a Primitive.
// Each value corresponds to one value of a per-primitive scope enum in
// common.proto (e.g. SignatureScope, AeadScope, KdfScope).
//
// Scope values are NOT globally unique — "standard" is valid for Signature,
// AEAD, MAC, etc. Uniqueness comes from the (Primitive, Scope) pair in ScopeSpec.
// Constants are grouped by primitive and prefixed for readability.
type Scope string

// ---------------------------------------------------------------------------
// Signature scopes  (from SignatureScope enum)
// ---------------------------------------------------------------------------

const (
	SignatureScopeStandard             Scope = "standard"
	SignatureScopeWithContext          Scope = "with_context"
	SignatureScopePrehashed            Scope = "prehashed"
	SignatureScopePrehashedWithContext Scope = "prehashed_with_context"
)

// ---------------------------------------------------------------------------
// AEAD scopes  (from AeadScope enum)
// ---------------------------------------------------------------------------

const (
	AeadScopeStandard      Scope = "standard"
	AeadScopeDeterministic Scope = "deterministic"
	AeadScopeStreaming     Scope = "streaming"
	AeadScopeTweakable     Scope = "tweakable"
)

// ---------------------------------------------------------------------------
// MAC scopes  (from MacScope enum)
// ---------------------------------------------------------------------------

const (
	MacScopeStandard  Scope = "standard"
	MacScopeStreaming Scope = "streaming"
)

// ---------------------------------------------------------------------------
// KEM scopes  (from KemScope enum)
// ---------------------------------------------------------------------------

const (
	KemScopeStandard Scope = "standard"
	KemScopeHybrid   Scope = "hybrid"
)

// ---------------------------------------------------------------------------
// Key Agreement scopes  (from KeyAgreementScope enum)
// ---------------------------------------------------------------------------

const (
	KeyAgreementScopeStandard Scope = "standard"
	KeyAgreementScopeHybrid   Scope = "hybrid"
)

// ---------------------------------------------------------------------------
// KDF scopes  (from KdfScope enum)
// ---------------------------------------------------------------------------

const (
	KdfScopeExtractExpand Scope = "extract_expand"
	KdfScopePassword      Scope = "password"
	KdfScopeAgreement     Scope = "agreement"
	KdfScopeCounter       Scope = "counter"
	KdfScopeTLS           Scope = "tls"
	KdfScopeGOST          Scope = "gost"
	KdfScopeVendor        Scope = "vendor"
)

// ---------------------------------------------------------------------------
// Hash scopes  (from HashScope enum)
// ---------------------------------------------------------------------------

const (
	HashScopeStandard Scope = "standard"
	HashScopeXOF      Scope = "xof"
)

// ---------------------------------------------------------------------------
// Key Wrapping scopes  (from KeyWrappingScope enum)
// ---------------------------------------------------------------------------

const (
	KeyWrappingScopeStandard    Scope = "standard"
	KeyWrappingScopeWithPadding Scope = "with_padding"
)

// ---------------------------------------------------------------------------
// Symmetric Cipher scopes  (from SymmetricCipherScope enum)
// ---------------------------------------------------------------------------

const (
	SymmetricCipherScopeBlock  Scope = "block"
	SymmetricCipherScopeStream Scope = "stream"
)

// ---------------------------------------------------------------------------
// Generic Secret scopes  (from GenericSecretScope enum)
// ---------------------------------------------------------------------------

const (
	GenericSecretScopeStandard Scope = "standard"
)

// ScopeSpec identifies a cryptographic scope for template selection.
// The (Primitive, Scope) pair maps 1:1 to a specific variant of the
// proto ScopeSpecification oneof.
//
// A zero-value ScopeSpec (both fields empty) means "no scope filter" —
// matches all templates regardless of scope.
//
// TODO: expand to carry UniversalSecurityProperties (fips_approved,
// quantum_safe, etc.) and per-primitive typed properties (non_malleable,
// deterministic, etc.) from the proto *ScopeSpec messages. Currently
// these are handled via the preferred map[string]string parameter in
// Select and the template's algorithm_properties map.
type ScopeSpec struct {
	Primitive Primitive // which cryptographic primitive (signature, aead, ...)
	Scope     Scope     // which operational variant within the primitive
}

// IsZero reports whether this ScopeSpec has no scope constraint.
func (s ScopeSpec) IsZero() bool {
	return s.Primitive == "" && s.Scope == ""
}
