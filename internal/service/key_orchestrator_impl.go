package service

import (
	"context"
	"fmt"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	types "github.ibm.com/citius/citius-server/gen/go/types"

	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/template"
	"google.golang.org/protobuf/proto"
)

// keyOrchestrator implements the KeyOrchestrator interface.
// It requires key.Repository, template.Registry, provider.Registry, and policy.Engine to function.
type keyOrchestrator struct {
	repo      key.Repository
	templates template.Registry
	providers provider.Registry
	policy    policy.Engine
}

// NewKeyOrchestrator creates a new KeyOrchestrator.
// All four dependencies are required; returns an error if any is nil.
func NewKeyOrchestrator(
	repo key.Repository,
	tr template.Registry,
	pr provider.Registry,
	pe policy.Engine,
) (KeyOrchestrator, error) {
	const op errors.Op = "service.NewKeyOrchestrator"
	ctx := context.Background()

	if repo == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"repository must not be nil")
	}
	if tr == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"template registry must not be nil")
	}
	if pr == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"provider registry must not be nil")
	}
	if pe == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"policy engine must not be nil")
	}

	return &keyOrchestrator{
		repo:      repo,
		templates: tr,
		providers: pr,
		policy:    pe,
	}, nil
}

func (r *keyOrchestrator) CreateKey(ctx context.Context, req core.KeyCreationSpec) (*KeyMetadata, error) {
	const op errors.Op = "service.(keyOrchestrator).CreateKey"

	// 1. Validate request
	if req.Name == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"key name must not be empty")
	}
	if req.PolicyID == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"policy ID must not be empty")
	}

	// 2. Resolve template + derive scope.
	//    Two paths: explicit template_id OR scope-based selection.
	var tmpl *template.Template
	var scopeSpec core.ScopeSpec

	if req.TemplateID != "" {
		// Template-based path — direct lookup, no policy filter.
		var err error
		tmpl, err = r.templates.Get(ctx, req.TemplateID)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
		// Derive scope from the template's primary ScopedCapability.
		scopeSpec = tmpl.PrimaryScopeSpec()
	} else {
		// Scope-based path: parse the proto-encoded ScopeSpecification,
		// query policy for allowed templates, then ask the registry to select.
		var err error
		scopeSpec, err = template.ParseScopeSpecification(req.Scope)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}

		allowed, err := r.policy.AllowedTemplates(ctx, req.PolicyID, scopeSpec)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}

		var candidates template.CandidateSet
		if allowed == nil {
			// nil means bypass (no policy in the system) - all templates eligible.
			candidates = template.AllTemplates()
		} else {
			candidates = template.OnlyTemplates(allowed...)
		}

		tmpl, err = r.templates.Select(ctx, scopeSpec, candidates)
		if err != nil {
			return nil, errors.Wrap(ctx, op, err)
		}
	}

	// 2a. Policy: validate that create_key with this template is permitted.
	if err := r.policy.ValidateOperation(ctx, req.PolicyID,
		core.OperationCreateKey, tmpl.TemplateID(), ""); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// 2b. Policy: validate key configuration constraints (extractable, rotation, etc.)
	if err := r.policy.ValidateKeyCreation(ctx, req.PolicyID, &req); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// 3. Generate key material and persist key + initial version.
	return r.generateAndPersistKey(ctx, op, req, tmpl, scopeSpec)
}

// toKeyMetadata projects a key.Key and its current key.Version into the
// API-facing KeyMetadata. v may be nil; version-scoped fields are
// then left at their zero values.
func (r *keyOrchestrator) toKeyMetadata(ctx context.Context, k *key.Key, v *key.Version) (*KeyMetadata, error) {
	md := &KeyMetadata{
		Name:           k.GetName(),
		KeyID:          k.GetPublicId(),
		Primitive:      k.GetPrimitive(),
		Policy:         k.GetPolicyId(),
		LifecycleState: k.GetStatus(),
		Labels:         k.GetLabels(),
	}

	if data := k.GetScopeSpecification(); len(data) > 0 {
		// ScopeSpecification is stored as JSON-encoded core.ScopeSpec.
		if scopeSpec, err := core.ParseScopeSpec(ctx, data); err == nil {
			md.ScopeSpec = template.ScopeSpecToProto(scopeSpec)
		}
	}

	if v != nil {
		md.Version = v.GetVersion()
		md.TemplateID = v.GetTemplateId()
		md.Provider = v.GetProviderId()
		if tmpl, err := r.templates.Get(ctx, v.GetTemplateId()); err == nil {
			md.TemplateInfo = tmpl.Proto()
		}
	}

	return md, nil
}

// generateAndPersistKey handles provider key generation, proto marshaling, and
// repository persistence.  Extracted from CreateKey to keep cyclomatic
// complexity within linter limits.
func (r *keyOrchestrator) generateAndPersistKey(
	ctx context.Context,
	op errors.Op,
	req core.KeyCreationSpec,
	tmpl *template.Template,
	scopeSpec core.ScopeSpec,
) (*KeyMetadata, error) {
	// 1. Find a provider that supports this template.
	prov, err := r.providers.MatchForTemplate(ctx, tmpl.TemplateID())
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// 2. Generate key material via the provider.
	genResp, err := prov.GenerateKey(ctx, &providerpb.GenerateKeyRequest{
		Algorithm: tmpl.GetAlgorithm(),
	})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// 3. Build Key + initial Version, then persist.
	//
	// TODO: add saga compensation to prevent orphaned key
	// material if storage fails after provider key generation succeeds.
	keyID := core.NewID(core.KeyPrefix)
	versionID := fmt.Sprintf("%s:%d", keyID, 1)

	scopeBytes, err := scopeSpec.Serialize(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// Marshal the full GenerateKeyResponse so that both KeyMaterial (private)
	// and PublicKeyBytes are persisted.  The crypto orchestrator unmarshals to
	// pick the right bytes per operation (Sign => private, Verify => public).
	genRespBytes, err := proto.Marshal(genResp)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	k := key.NewKey(&storepb.Key{
		PublicId:           keyID,
		Name:               req.Name,
		Primitive:          scopeSpec.Primitive.String(),
		ScopeSpecification: scopeBytes,
		PolicyId:           req.PolicyID,
		CurrentVersion:     1,
		Status:             types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE,
		Labels:             req.Labels,
	})

	v := key.NewVersion(&storepb.KeyVersion{
		PublicId:    versionID,
		KeyId:       keyID,
		Version:     1,
		ProviderId:  prov.Name(),
		TemplateId:  tmpl.TemplateID(),
		KeyMaterial: genRespBytes,
		Status:      types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE,
	})

	if err := r.repo.CreateKey(ctx, k, v); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	return r.toKeyMetadata(ctx, k, v)
}

func (r *keyOrchestrator) ReadKey(ctx context.Context, keyName string, version uint32) (*KeyMetadata, error) {
	const op errors.Op = "service.(keyOrchestrator).ReadKey"
	k, err := r.repo.GetKeyByName(ctx, keyName)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	var v *key.Version
	if version == 0 {
		v, err = r.repo.GetCurrentVersion(ctx, k.GetPublicId())
	} else {
		v, err = r.repo.GetVersion(ctx, k.GetPublicId(), version)
	}
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	return r.toKeyMetadata(ctx, k, v)
}

func (r *keyOrchestrator) ListKeys(ctx context.Context) ([]*KeyMetadata, error) {
	const op errors.Op = "service.(keyOrchestrator).ListKeys"
	keys, err := r.repo.ListKeys(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}
	out := make([]*KeyMetadata, 0, len(keys))
	for _, k := range keys {
		v, verr := r.repo.GetCurrentVersion(ctx, k.GetPublicId())
		if verr != nil {
			return nil, errors.Wrap(ctx, op, verr)
		}
		md, merr := r.toKeyMetadata(ctx, k, v)
		if merr != nil {
			return nil, errors.Wrap(ctx, op, merr)
		}
		out = append(out, md)
	}
	return out, nil
}

func (r *keyOrchestrator) DeleteKey(ctx context.Context, keyName string) error {
	const op errors.Op = "service.(keyOrchestrator).DeleteKey"
	// 1. Fetch key metadata.
	k, err := r.repo.GetKeyByName(ctx, keyName)
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}

	if err := r.repo.DeleteKey(ctx, k.GetPublicId()); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

func (r *keyOrchestrator) RotateKey(ctx context.Context, _ string) (*KeyMetadata, error) {
	return nil, errors.New(ctx, "service.(keyOrchestrator).RotateKey", errors.CodeNotImplemented,
		"RotateKey not yet implemented")
}

func (r *keyOrchestrator) SuspendKey(ctx context.Context, _ string) error {
	return errors.New(ctx, "service.(keyOrchestrator).SuspendKey", errors.CodeNotImplemented,
		"SuspendKey not yet implemented")
}

func (r *keyOrchestrator) RestoreKey(ctx context.Context, _ string) error {
	return errors.New(ctx, "service.(keyOrchestrator).RestoreKey", errors.CodeNotImplemented,
		"RestoreKey not yet implemented")
}

func (r *keyOrchestrator) DestroyKey(ctx context.Context, _ string) error {
	return errors.New(ctx, "service.(keyOrchestrator).DestroyKey", errors.CodeNotImplemented,
		"DestroyKey not yet implemented")
}

func (r *keyOrchestrator) ImportKey(ctx context.Context, _ core.ImportKeySpec) (*KeyMetadata, error) {
	return nil, errors.New(ctx, "service.(keyOrchestrator).ImportKey", errors.CodeNotImplemented,
		"ImportKey not yet implemented")
}

func (r *keyOrchestrator) UpdateKeyPolicy(ctx context.Context, _ string, _ string) error {
	return errors.New(ctx, "service.(keyOrchestrator).UpdateKeyPolicy", errors.CodeNotImplemented,
		"UpdateKeyPolicy not yet implemented")
}

// Compile-time assertion: keyOrchestrator implements KeyOrchestrator.
var _ KeyOrchestrator = (*keyOrchestrator)(nil)
