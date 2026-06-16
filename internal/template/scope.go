package template

import (
	"context"

	api "github.ibm.com/citius/citius-server/gen/go/api/types"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"google.golang.org/protobuf/proto"
)

// ParseScopeSpecification converts proto-encoded ScopeSpecification bytes
// into a core.ScopeSpec.
//
// This function lives in the template package because the template bounded
// context owns the mapping from proto ScopeSpecification (a deeply nested
// oneof with many primitive variants) to the domain-level core.ScopeSpec.
// The same mapping is used internally by Select, MatchesScope, and
// PrimaryScopeSpec — ParseScopeSpecification is the exported entry point
// for callers who receive scope data as proto wire bytes (e.g. the service
// layer deserializing core.KeyCreationSpec.Scope from a gRPC request).
//
// Returns an error if data is empty or not valid proto-encoded ScopeSpecification.
func ParseScopeSpecification(data []byte) (core.ScopeSpec, error) {
	const op errors.Op = "template.ParseScopeSpecification"
	if len(data) == 0 {
		return core.ScopeSpec{}, errors.New(context.TODO(), op, errors.CodeInvalidArgument,
			"scope specification bytes must not be empty")
	}
	spec := &api.ScopeSpecification{}
	if err := proto.Unmarshal(data, spec); err != nil {
		return core.ScopeSpec{}, errors.New(context.TODO(), op, errors.CodeInvalidArgument,
			"invalid scope specification: "+err.Error())
	}
	return scopeSpecFromProto(spec), nil
}

// ScopeSpecToProto converts a core.ScopeSpec back to its proto representation.
// This is the inverse of scopeSpecFromProto. Returns nil for a zero-value ScopeSpec.
func ScopeSpecToProto(s core.ScopeSpec) *api.ScopeSpecification {
	if s.IsZero() {
		return nil
	}
	sec := securityToProto(s)
	switch s.Primitive {
	case core.PrimitiveSignature:
		return &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_Signature{
			Signature: &api.SignatureScopeSpec{Scope: signatureScopeFromCore(s.Scope), Security: sec},
		}}
	case core.PrimitiveAead:
		return &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_Aead{
			Aead: &api.AeadScopeSpec{Scope: aeadScopeFromCore(s.Scope), Security: sec},
		}}
	case core.PrimitiveMac:
		return &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_Mac{
			Mac: &api.MacScopeSpec{Scope: macScopeFromCore(s.Scope), Security: sec},
		}}
	case core.PrimitiveKem:
		return &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_Kem{
			Kem: &api.KemScopeSpec{Scope: kemScopeFromCore(s.Scope), Security: sec},
		}}
	case core.PrimitiveKeyAgreement:
		return &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_KeyAgreement{
			KeyAgreement: &api.KeyAgreementScopeSpec{Scope: keyAgreementScopeFromCore(s.Scope), Security: sec},
		}}
	case core.PrimitiveKdf:
		return &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_Kdf{
			Kdf: &api.KdfScopeSpec{Scope: kdfScopeFromCore(s.Scope), Security: sec},
		}}
	case core.PrimitiveHash:
		return &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_Hash{
			Hash: &api.HashScopeSpec{Scope: hashScopeFromCore(s.Scope), Security: sec},
		}}
	case core.PrimitiveKeyWrapping:
		return &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_KeyWrapping{
			KeyWrapping: &api.KeyWrappingScopeSpec{Scope: keyWrappingScopeFromCore(s.Scope), Security: sec},
		}}
	case core.PrimitiveSymmetricCipher:
		return &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_SymmetricCipher{
			SymmetricCipher: &api.SymmetricCipherScopeSpec{Scope: symmetricCipherScopeFromCore(s.Scope), Security: sec},
		}}
	case core.PrimitiveGenericSecret:
		return &api.ScopeSpecification{ScopeSpec: &api.ScopeSpecification_GenericSecret{
			GenericSecret: &api.GenericSecretScopeSpec{Scope: genericSecretScopeFromCore(s.Scope), Security: sec},
		}}
	default:
		return nil
	}
}

func securityToProto(s core.ScopeSpec) *api.UniversalSecurityProperties {
	if s.FIPSApproved == nil && s.QuantumSafe == nil {
		return nil
	}
	sec := &api.UniversalSecurityProperties{}
	if s.FIPSApproved != nil {
		v := *s.FIPSApproved
		sec.FipsApproved = &v
	}
	if s.QuantumSafe != nil {
		v := *s.QuantumSafe
		sec.QuantumSafe = &v
	}
	return sec
}

func signatureScopeFromCore(s core.Scope) api.SignatureScope {
	switch s {
	case core.SignatureScopeStandard:
		return api.SignatureScope_SIGNATURE_SCOPE_STANDARD
	case core.SignatureScopeWithContext:
		return api.SignatureScope_SIGNATURE_SCOPE_WITH_CONTEXT
	case core.SignatureScopePrehashed:
		return api.SignatureScope_SIGNATURE_SCOPE_PREHASHED
	case core.SignatureScopePrehashedWithContext:
		return api.SignatureScope_SIGNATURE_SCOPE_PREHASHED_WITH_CONTEXT
	default:
		return api.SignatureScope_SIGNATURE_SCOPE_UNSPECIFIED
	}
}

func aeadScopeFromCore(s core.Scope) api.AeadScope {
	switch s {
	case core.AeadScopeStandard:
		return api.AeadScope_AEAD_SCOPE_STANDARD
	case core.AeadScopeDeterministic:
		return api.AeadScope_AEAD_SCOPE_DETERMINISTIC
	case core.AeadScopeStreaming:
		return api.AeadScope_AEAD_SCOPE_STREAMING
	default:
		return api.AeadScope_AEAD_SCOPE_UNSPECIFIED
	}
}

func macScopeFromCore(s core.Scope) api.MacScope {
	switch s {
	case core.MacScopeStandard:
		return api.MacScope_MAC_SCOPE_STANDARD
	case core.MacScopeStreaming:
		return api.MacScope_MAC_SCOPE_STREAMING
	default:
		return api.MacScope_MAC_SCOPE_UNSPECIFIED
	}
}

func kemScopeFromCore(s core.Scope) api.KemScope {
	switch s {
	case core.KemScopeStandard:
		return api.KemScope_KEM_SCOPE_STANDARD
	case core.KemScopeHybrid:
		return api.KemScope_KEM_SCOPE_HYBRID
	default:
		return api.KemScope_KEM_SCOPE_UNSPECIFIED
	}
}

func keyAgreementScopeFromCore(s core.Scope) api.KeyAgreementScope {
	switch s {
	case core.KeyAgreementScopeStandard:
		return api.KeyAgreementScope_KEY_AGREEMENT_SCOPE_STANDARD
	case core.KeyAgreementScopeHybrid:
		return api.KeyAgreementScope_KEY_AGREEMENT_SCOPE_HYBRID
	default:
		return api.KeyAgreementScope_KEY_AGREEMENT_SCOPE_UNSPECIFIED
	}
}

func kdfScopeFromCore(s core.Scope) api.KdfScope {
	switch s {
	case core.KdfScopeExtractExpand:
		return api.KdfScope_KDF_SCOPE_EXTRACT_EXPAND
	case core.KdfScopePassword:
		return api.KdfScope_KDF_SCOPE_PASSWORD
	case core.KdfScopeAgreement:
		return api.KdfScope_KDF_SCOPE_AGREEMENT
	case core.KdfScopeCounter:
		return api.KdfScope_KDF_SCOPE_COUNTER
	case core.KdfScopeTLS:
		return api.KdfScope_KDF_SCOPE_TLS
	case core.KdfScopeGOST:
		return api.KdfScope_KDF_SCOPE_GOST
	case core.KdfScopeVendor:
		return api.KdfScope_KDF_SCOPE_VENDOR
	default:
		return api.KdfScope_KDF_SCOPE_UNSPECIFIED
	}
}

func hashScopeFromCore(s core.Scope) api.HashScope {
	switch s {
	case core.HashScopeStandard:
		return api.HashScope_HASH_SCOPE_STANDARD
	case core.HashScopeXOF:
		return api.HashScope_HASH_SCOPE_XOF
	default:
		return api.HashScope_HASH_SCOPE_UNSPECIFIED
	}
}

func keyWrappingScopeFromCore(s core.Scope) api.KeyWrappingScope {
	switch s {
	case core.KeyWrappingScopeStandard:
		return api.KeyWrappingScope_KEY_WRAPPING_SCOPE_STANDARD
	case core.KeyWrappingScopeWithPadding:
		return api.KeyWrappingScope_KEY_WRAPPING_SCOPE_WITH_PADDING
	default:
		return api.KeyWrappingScope_KEY_WRAPPING_SCOPE_UNSPECIFIED
	}
}

func symmetricCipherScopeFromCore(s core.Scope) api.SymmetricCipherScope {
	switch s {
	case core.SymmetricCipherScopeBlock:
		return api.SymmetricCipherScope_SYMMETRIC_CIPHER_SCOPE_BLOCK
	case core.SymmetricCipherScopeStream:
		return api.SymmetricCipherScope_SYMMETRIC_CIPHER_SCOPE_STREAM
	default:
		return api.SymmetricCipherScope_SYMMETRIC_CIPHER_SCOPE_UNSPECIFIED
	}
}

func genericSecretScopeFromCore(s core.Scope) api.GenericSecretScope {
	switch s {
	case core.GenericSecretScopeStandard:
		return api.GenericSecretScope_GENERIC_SECRET_SCOPE_STANDARD
	default:
		return api.GenericSecretScope_GENERIC_SECRET_SCOPE_UNSPECIFIED
	}
}
