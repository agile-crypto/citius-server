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
//  1. If allowedTemplates has one entry and scope/preferred are empty,
//     treat it as a direct lookup (fast path for template_id=explicit case).
//  2. Build candidates: all templates matching the scope (if scope is set).
//  3. Filter by allowedTemplates (if non-empty).
//  4. Filter by preferred properties (e.g. quantum_safe=true).
//  5. Return first remaining candidate, or CodeTemplateNotFound.
//
// NOTE: Select accesses r.templates (logical.Storage) directly using readlock rather than
// calling r.Get()/r.List(), because those methods also acquire r.mu.RLock()
// and Go's sync.RWMutex is NOT reentrant.
// TODO: Optimize with caching instead of full storage scan with serialization and deserialization
func (r *VaultRegistry) Select(ctx context.Context, scopeSpec core.ScopeSpec, allowedTemplates []string, preferred map[string]string) (*Template, error) {
	const op errors.Op = "template.(VaultRegistry).Select"
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Fast path: explicit template ID lookup (single allowed, no scope/properties)
	if len(allowedTemplates) == 1 && len(preferred) == 0 && scopeSpec.IsZero() {
		entry, err := r.templates.Get(ctx, allowedTemplates[0])
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		if entry == nil {
			return nil, errors.New(ctx, op, errors.CodeTemplateNotFound,
				"template not found: "+allowedTemplates[0])
		}
		stored := &api.TemplateInfo{}
		if err := proto.Unmarshal(entry.Value, stored); err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		return NewTemplate(stored), nil
	}

	// Load all templates from storage
	ids, err := r.templates.List(ctx, "")
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// Step 1: build candidates (all templates, or scope-filtered)
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

	// Step 2: filter by AllowedTemplates
	if len(allowedTemplates) > 0 {
		allowed := make(map[string]struct{}, len(allowedTemplates))
		for _, id := range allowedTemplates {
			allowed[id] = struct{}{}
		}
		filtered := candidates[:0]
		for _, t := range candidates {
			if _, ok := allowed[t.TemplateID()]; ok {
				filtered = append(filtered, t)
			}
		}
		candidates = filtered
	}

	// Step 3: filter by preferred properties
	// Properties are checked against the template's algorithm_properties map —
	// the flattened search index with keys like quantum_safe, fips_approved.
	if len(preferred) > 0 {
		filtered := candidates[:0]
		for _, t := range candidates {
			if MatchesProperties(t, preferred) {
				filtered = append(filtered, t)
			}
		}
		candidates = filtered
	}

	if len(candidates) == 0 {
		return nil, errors.New(ctx, op, errors.CodeTemplateNotFound,
			"no template matches the selection criteria")
	}

	// Step 4: return first candidate (deterministic — storage iteration order)
	return candidates[0].Clone(), nil
}

// ---------------------------------------------------------------------------
// Proto -> Domain conversion (package-internal see doc.go)
// ---------------------------------------------------------------------------

// scopeSpecFromProto converts a proto ScopeSpecification to a core.ScopeSpec.
// Extracts both the Primitive (from the oneof variant) and the Scope
// (from the per-primitive scope enum value).
// Returns zero-value ScopeSpec if spec is nil.
func scopeSpecFromProto(spec *api.ScopeSpecification) core.ScopeSpec {
	if spec == nil {
		return core.ScopeSpec{}
	}
	switch s := spec.GetScopeSpec().(type) {
	case *api.ScopeSpecification_Signature:
		return core.ScopeSpec{
			Primitive: core.PrimitiveSignature,
			Scope:     signatureScopeToCore(s.Signature.GetScope()),
		}
	case *api.ScopeSpecification_Aead:
		return core.ScopeSpec{
			Primitive: core.PrimitiveAead,
			Scope:     aeadScopeToCore(s.Aead.GetScope()),
		}
	case *api.ScopeSpecification_Mac:
		return core.ScopeSpec{
			Primitive: core.PrimitiveMac,
			Scope:     macScopeToCore(s.Mac.GetScope()),
		}
	case *api.ScopeSpecification_Kem:
		return core.ScopeSpec{
			Primitive: core.PrimitiveKem,
			Scope:     kemScopeToCore(s.Kem.GetScope()),
		}
	case *api.ScopeSpecification_KeyAgreement:
		return core.ScopeSpec{
			Primitive: core.PrimitiveKeyAgreement,
			Scope:     keyAgreementScopeToCore(s.KeyAgreement.GetScope()),
		}
	case *api.ScopeSpecification_Kdf:
		return core.ScopeSpec{
			Primitive: core.PrimitiveKdf,
			Scope:     kdfScopeToCore(s.Kdf.GetScope()),
		}
	case *api.ScopeSpecification_Hash:
		return core.ScopeSpec{
			Primitive: core.PrimitiveHash,
			Scope:     hashScopeToCore(s.Hash.GetScope()),
		}
	case *api.ScopeSpecification_KeyWrapping:
		return core.ScopeSpec{
			Primitive: core.PrimitiveKeyWrapping,
			Scope:     keyWrappingScopeToCore(s.KeyWrapping.GetScope()),
		}
	case *api.ScopeSpecification_SymmetricCipher:
		return core.ScopeSpec{
			Primitive: core.PrimitiveSymmetricCipher,
			Scope:     symmetricCipherScopeToCore(s.SymmetricCipher.GetScope()),
		}
	case *api.ScopeSpecification_GenericSecret:
		return core.ScopeSpec{
			Primitive: core.PrimitiveGenericSecret,
			Scope:     genericSecretScopeToCore(s.GenericSecret.GetScope()),
		}
	default:
		return core.ScopeSpec{}
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
