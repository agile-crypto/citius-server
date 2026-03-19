package template

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/sdk/logical"
	api "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"google.golang.org/protobuf/proto"
)

const templateStoragePrefix = "template/"

var _ Registry = (*VaultRegistry)(nil)

// VaultRegistry is a Vault-backed implementation of the Registry interface.
// Uses logical.Storage (typically logical.InmemStorage) with proto serialization,
// following the same pattern as VaultRepository in key, policy, and provider.
type VaultRegistry struct {
	mu        *sync.RWMutex
	templates logical.Storage
}

// NewVaultRegistry creates a VaultRegistry backed by the given storage.
// For in-memory usage, pass &logical.InmemStorage{}.
func NewVaultRegistry(ctx context.Context, storage logical.Storage, opt ...Option) (*VaultRegistry, error) {
	const op errors.Op = "template.NewVaultRegistry"
	if storage == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "nil storage")
	}
	opts := getOpts(opt...)
	return &VaultRegistry{
		mu:        opts.withLock,
		templates: logical.NewStorageView(storage, templateStoragePrefix),
	}, nil
}

// Register stores a template. If a template with the same ID already exists,
// it is overwritten (permits startup re-loading).
func (r *VaultRegistry) Register(ctx context.Context, t *Template) error {
	const op errors.Op = "template.(VaultRegistry).Register"
	if t == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "template must not be nil")
	}
	if t.TemplateID() == "" {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "template ID must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, err := proto.Marshal(t.stored)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}
	entry := &logical.StorageEntry{Key: t.TemplateID(), Value: b}
	if err := r.templates.Put(ctx, entry); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// Get returns the template with the given ID, or a CodeTemplateNotFound error.
// Returns an independent copy via proto round-trip (marshal on Register, unmarshal on Get).
func (r *VaultRegistry) Get(ctx context.Context, templateID string) (*Template, error) {
	const op errors.Op = "template.(VaultRegistry).Get"
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, err := r.templates.Get(ctx, templateID)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	if entry == nil {
		return nil, errors.New(ctx, op, errors.CodeTemplateNotFound,
			"template not found: "+templateID)
	}
	stored := &api.TemplateInfo{}
	if err := proto.Unmarshal(entry.Value, stored); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return NewTemplate(stored), nil
}

// List returns all registered templates.
func (r *VaultRegistry) List(ctx context.Context) []*Template {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids, err := r.templates.List(ctx, "")
	if err != nil {
		return []*Template{}
	}
	out := make([]*Template, 0, len(ids))
	for _, id := range ids {
		entry, err := r.templates.Get(ctx, id)
		if err != nil || entry == nil {
			continue
		}
		stored := &api.TemplateInfo{}
		if err := proto.Unmarshal(entry.Value, stored); err != nil {
			continue
		}
		out = append(out, NewTemplate(stored))
	}
	return out
}

// Select returns the best-matching template for the given request.
// The selection algorithm:
//  1. If candidates is restricted to one entry and scope is zero,
//     treat it as a direct lookup (fast path for template_id=explicit case).
//  2. Determine the candidate ID set: when candidates is restricted,
//     only those IDs are deserialized; when unrestricted, all stored IDs
//     are loaded (avoids deserializing templates the policy already excludes).
//  3. Deserialize each candidate and apply scope + security filters.
//  4. Return first matching candidate, or CodeTemplateNotFound.
//
// Security filtering (fips_approved, quantum_safe) is part of scope matching:
// the caller's ScopeSpec carries typed security filter fields, matched against
// each template's ScopedCapabilities[].Scope.security (UniversalSecurityProperties).
//
// NOTE: Select accesses r.templates (logical.Storage) directly using readlock rather than
// calling r.Get()/r.List(), because those methods also acquire r.mu.RLock()
// and Go's sync.RWMutex is NOT reentrant.
// TODO: Optimize with caching instead of full storage scan with serialization and deserialization
func (r *VaultRegistry) Select(ctx context.Context, scopeSpec core.ScopeSpec, cs CandidateSet) (*Template, error) {
	const op errors.Op = "template.(VaultRegistry).Select"
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Fast path: explicit template ID lookup (single restricted ID, no scope/security filters)
	if cs.IsRestricted() && len(cs.IDs()) == 1 && scopeSpec.IsZero() {
		entry, err := r.templates.Get(ctx, cs.IDs()[0])
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		if entry == nil {
			return nil, errors.New(ctx, op, errors.CodeTemplateNotFound,
				"template not found: "+cs.IDs()[0])
		}
		stored := &api.TemplateInfo{}
		if err := proto.Unmarshal(entry.Value, stored); err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return NewTemplate(stored), nil
	}

	// Step 1: determine the candidate ID set.
	// When the caller restricts to specific IDs, only those are eligible
	// (no point deserializing templates we already know the policy excludes).
	// When unrestricted, every stored template is a candidate.
	var ids []string
	if cs.IsRestricted() {
		ids = cs.IDs()
	} else {
		var err error
		ids, err = r.templates.List(ctx, "")
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
	}

	// Step 2: deserialize each candidate and apply scope + security filter.
	var candidates []*Template
	for _, id := range ids {
		entry, err := r.templates.Get(ctx, id)
		if err != nil || entry == nil {
			continue
		}
		stored := &api.TemplateInfo{}
		if err := proto.Unmarshal(entry.Value, stored); err != nil {
			continue
		}
		t := NewTemplate(stored)
		if MatchesScope(t, scopeSpec) {
			candidates = append(candidates, t)
		}
	}

	if len(candidates) == 0 {
		return nil, errors.New(ctx, op, errors.CodeTemplateNotFound,
			"no template matches the selection criteria")
	}

	// Step 3: return first candidate (deterministic — storage/candidates iteration order)
	return candidates[0].Clone(), nil
}

// ---------------------------------------------------------------------------
// Proto -> Domain conversion (package-internal see doc.go)
// ---------------------------------------------------------------------------

// scopeSpecFromProto converts a proto ScopeSpecification to a core.ScopeSpec.
// Extracts both the Primitive (from the oneof variant) and the Scope
// (from the per-primitive scope enum value).
// Also extracts UniversalSecurityProperties (fips_approved, quantum_safe)
// from the per-primitive security field.
// Returns zero-value ScopeSpec if spec is nil.
func scopeSpecFromProto(spec *api.ScopeSpecification) core.ScopeSpec {
	if spec == nil {
		return core.ScopeSpec{}
	}
	switch s := spec.GetScopeSpec().(type) {
	case *api.ScopeSpecification_Signature:
		result := core.ScopeSpec{
			Primitive: core.PrimitiveSignature,
			Scope:     signatureScopeToCore(s.Signature.GetScope()),
		}
		extractSecurity(&result, s.Signature.GetSecurity())
		return result
	case *api.ScopeSpecification_Aead:
		result := core.ScopeSpec{
			Primitive: core.PrimitiveAead,
			Scope:     aeadScopeToCore(s.Aead.GetScope()),
		}
		extractSecurity(&result, s.Aead.GetSecurity())
		return result
	case *api.ScopeSpecification_Mac:
		result := core.ScopeSpec{
			Primitive: core.PrimitiveMac,
			Scope:     macScopeToCore(s.Mac.GetScope()),
		}
		extractSecurity(&result, s.Mac.GetSecurity())
		return result
	case *api.ScopeSpecification_Kem:
		result := core.ScopeSpec{
			Primitive: core.PrimitiveKem,
			Scope:     kemScopeToCore(s.Kem.GetScope()),
		}
		extractSecurity(&result, s.Kem.GetSecurity())
		return result
	case *api.ScopeSpecification_KeyAgreement:
		result := core.ScopeSpec{
			Primitive: core.PrimitiveKeyAgreement,
			Scope:     keyAgreementScopeToCore(s.KeyAgreement.GetScope()),
		}
		extractSecurity(&result, s.KeyAgreement.GetSecurity())
		return result
	case *api.ScopeSpecification_Kdf:
		result := core.ScopeSpec{
			Primitive: core.PrimitiveKdf,
			Scope:     kdfScopeToCore(s.Kdf.GetScope()),
		}
		extractSecurity(&result, s.Kdf.GetSecurity())
		return result
	case *api.ScopeSpecification_Hash:
		result := core.ScopeSpec{
			Primitive: core.PrimitiveHash,
			Scope:     hashScopeToCore(s.Hash.GetScope()),
		}
		extractSecurity(&result, s.Hash.GetSecurity())
		return result
	case *api.ScopeSpecification_KeyWrapping:
		result := core.ScopeSpec{
			Primitive: core.PrimitiveKeyWrapping,
			Scope:     keyWrappingScopeToCore(s.KeyWrapping.GetScope()),
		}
		extractSecurity(&result, s.KeyWrapping.GetSecurity())
		return result
	case *api.ScopeSpecification_SymmetricCipher:
		result := core.ScopeSpec{
			Primitive: core.PrimitiveSymmetricCipher,
			Scope:     symmetricCipherScopeToCore(s.SymmetricCipher.GetScope()),
		}
		extractSecurity(&result, s.SymmetricCipher.GetSecurity())
		return result
	case *api.ScopeSpecification_GenericSecret:
		result := core.ScopeSpec{
			Primitive: core.PrimitiveGenericSecret,
			Scope:     genericSecretScopeToCore(s.GenericSecret.GetScope()),
		}
		extractSecurity(&result, s.GenericSecret.GetSecurity())
		return result
	default:
		return core.ScopeSpec{}
	}
}

// extractSecurity populates ScopeSpec security fields from UniversalSecurityProperties.
// Uses proto optional field semantics: nil → don't set, non-nil → set value.
func extractSecurity(s *core.ScopeSpec, sec *api.UniversalSecurityProperties) {
	if sec == nil {
		return
	}
	if sec.FipsApproved != nil {
		v := sec.GetFipsApproved()
		s.FIPSApproved = &v
	}
	if sec.QuantumSafe != nil {
		v := sec.GetQuantumSafe()
		s.QuantumSafe = &v
	}
}

// ---------------------------------------------------------------------------
// Per-primitive scope enum → core.Scope converters
// ---------------------------------------------------------------------------

func signatureScopeToCore(s api.SignatureScope) core.Scope {
	switch s {
	case api.SignatureScope_SIGNATURE_SCOPE_STANDARD:
		return core.SignatureScopeStandard
	case api.SignatureScope_SIGNATURE_SCOPE_WITH_CONTEXT:
		return core.SignatureScopeWithContext
	case api.SignatureScope_SIGNATURE_SCOPE_PREHASHED:
		return core.SignatureScopePrehashed
	case api.SignatureScope_SIGNATURE_SCOPE_PREHASHED_WITH_CONTEXT:
		return core.SignatureScopePrehashedWithContext
	default:
		return ""
	}
}

func aeadScopeToCore(s api.AeadScope) core.Scope {
	switch s {
	case api.AeadScope_AEAD_SCOPE_STANDARD:
		return core.AeadScopeStandard
	case api.AeadScope_AEAD_SCOPE_DETERMINISTIC:
		return core.AeadScopeDeterministic
	case api.AeadScope_AEAD_SCOPE_STREAMING:
		return core.AeadScopeStreaming
	case api.AeadScope_AEAD_SCOPE_TWEAKABLE:
		return core.AeadScopeTweakable
	default:
		return ""
	}
}

func macScopeToCore(s api.MacScope) core.Scope {
	switch s {
	case api.MacScope_MAC_SCOPE_STANDARD:
		return core.MacScopeStandard
	case api.MacScope_MAC_SCOPE_STREAMING:
		return core.MacScopeStreaming
	default:
		return ""
	}
}

func kemScopeToCore(s api.KemScope) core.Scope {
	switch s {
	case api.KemScope_KEM_SCOPE_STANDARD:
		return core.KemScopeStandard
	case api.KemScope_KEM_SCOPE_HYBRID:
		return core.KemScopeHybrid
	default:
		return ""
	}
}

func keyAgreementScopeToCore(s api.KeyAgreementScope) core.Scope {
	switch s {
	case api.KeyAgreementScope_KEY_AGREEMENT_SCOPE_STANDARD:
		return core.KeyAgreementScopeStandard
	case api.KeyAgreementScope_KEY_AGREEMENT_SCOPE_HYBRID:
		return core.KeyAgreementScopeHybrid
	default:
		return ""
	}
}

func kdfScopeToCore(s api.KdfScope) core.Scope {
	switch s {
	case api.KdfScope_KDF_SCOPE_EXTRACT_EXPAND:
		return core.KdfScopeExtractExpand
	case api.KdfScope_KDF_SCOPE_PASSWORD:
		return core.KdfScopePassword
	case api.KdfScope_KDF_SCOPE_AGREEMENT:
		return core.KdfScopeAgreement
	case api.KdfScope_KDF_SCOPE_COUNTER:
		return core.KdfScopeCounter
	case api.KdfScope_KDF_SCOPE_TLS:
		return core.KdfScopeTLS
	case api.KdfScope_KDF_SCOPE_GOST:
		return core.KdfScopeGOST
	case api.KdfScope_KDF_SCOPE_VENDOR:
		return core.KdfScopeVendor
	default:
		return ""
	}
}

func hashScopeToCore(s api.HashScope) core.Scope {
	switch s {
	case api.HashScope_HASH_SCOPE_STANDARD:
		return core.HashScopeStandard
	case api.HashScope_HASH_SCOPE_XOF:
		return core.HashScopeXOF
	default:
		return ""
	}
}

func keyWrappingScopeToCore(s api.KeyWrappingScope) core.Scope {
	switch s {
	case api.KeyWrappingScope_KEY_WRAPPING_SCOPE_STANDARD:
		return core.KeyWrappingScopeStandard
	case api.KeyWrappingScope_KEY_WRAPPING_SCOPE_WITH_PADDING:
		return core.KeyWrappingScopeWithPadding
	default:
		return ""
	}
}

func symmetricCipherScopeToCore(s api.SymmetricCipherScope) core.Scope {
	switch s {
	case api.SymmetricCipherScope_SYMMETRIC_CIPHER_SCOPE_BLOCK:
		return core.SymmetricCipherScopeBlock
	case api.SymmetricCipherScope_SYMMETRIC_CIPHER_SCOPE_STREAM:
		return core.SymmetricCipherScopeStream
	default:
		return ""
	}
}

func genericSecretScopeToCore(s api.GenericSecretScope) core.Scope {
	switch s {
	case api.GenericSecretScope_GENERIC_SECRET_SCOPE_STANDARD:
		return core.GenericSecretScopeStandard
	default:
		return ""
	}
}
