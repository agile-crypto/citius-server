package core

import (
	"context"
	"encoding/json"

	"github.ibm.com/citius/citius-server/internal/errors"
)

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

func (p Primitive) String() string {
	return string(p)
}

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
// A zero-value ScopeSpec (all fields empty/nil) means "no scope filter" —
// matches all templates regardless of scope.
//
// Security filters are typed fields extracted from the proto's
// UniversalSecurityProperties (inside ScopeSpecification.<primitive>.security).
// These replace the former preferred map[string]string parameter in Select
// and the removed algorithm_properties flat map on TemplateInfo.
//
// TODO: expand to carry per-primitive typed properties (non_malleable,
// deterministic, nonce_misuse_resistant, forward_secrecy, etc.) from the
// per-primitive *ScopeSpec messages in common.proto.
type ScopeSpec struct {
	Primitive Primitive // which cryptographic primitive (signature, aead, ...)
	Scope     Scope     // which operational variant within the primitive

	// Security filters — nil means "don't filter", non-nil applies the filter.
	// Extracted from UniversalSecurityProperties in the proto ScopeSpecification.
	FIPSApproved *bool // if non-nil, template's scope.security.fips_approved must match
	QuantumSafe  *bool // if non-nil, template's scope.security.quantum_safe must match
}

// IsZero reports whether this ScopeSpec has no scope constraint and no security filters.
func (s ScopeSpec) IsZero() bool {
	return s.Primitive == "" && s.Scope == "" && s.FIPSApproved == nil && s.QuantumSafe == nil
}

// HasSecurityFilter reports whether this ScopeSpec has any security filter set.
func (s ScopeSpec) HasSecurityFilter() bool {
	return s.FIPSApproved != nil || s.QuantumSafe != nil
}

func (s *ScopeSpec) Serialize(ctx context.Context) ([]byte, error) {
	const op = "core.(ScopeSpec).Serialize"
	res, err := json.Marshal(s)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return res, nil
}

func ParseScopeSpec(ctx context.Context, data []byte) (ScopeSpec, error) {
	const op errors.Op = "core.ParseScopeSpec"
	if len(data) == 0 {
		return ScopeSpec{}, errors.New(ctx, op, errors.CodeInternal,
			"scope specification data is empty")
	}
	var s ScopeSpec
	if err := json.Unmarshal(data, &s); err != nil {
		return ScopeSpec{}, errors.Wrap(ctx, op, err)
	}
	return s, nil
}
