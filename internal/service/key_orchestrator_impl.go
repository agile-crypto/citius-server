package service

import (
	"context"
	"fmt"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/template"
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

func (r *keyOrchestrator) CreateKey(ctx context.Context, req core.KeyCreationSpec) (*key.Key, error) {
	const op errors.Op = "service.(keyOrchestrator).CreateKey"

	// 1. Validate request
	if req.Name == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"key name must not be empty")
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

	// 3. Find a provider that supports this template.
	prov, err := r.providers.MatchForTemplate(ctx, tmpl.TemplateID())
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// 4. Generate key material via the provider.
	genResp, err := prov.GenerateKey(ctx, &providerpb.GenerateKeyRequest{
		Algorithm: tmpl.GetAlgorithm(),
	})
	if err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	// 5. Build Key + initial Version, then persist.
	//
	// TODO: add saga compensation to prevent orphaned key
	// material if storage fails after provider key generation succeeds.
	keyID := core.NewID(core.KeyPrefix)
	versionID := fmt.Sprintf("%s:%d", keyID, 1)

	scopeBytes, err := scopeSpec.Serialize(ctx)
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
		Status:             storepb.KeyStatus_KEY_STATUS_ACTIVE,
		Labels:             req.Labels,
	})

	v := key.NewVersion(&storepb.KeyVersion{
		PublicId:    versionID,
		KeyId:       keyID,
		Version:     1,
		ProviderId:  prov.Name(),
		TemplateId:  tmpl.TemplateID(),
		KeyMaterial: genResp.GetKeyMaterial(),
		Status:      storepb.KeyStatus_KEY_STATUS_ACTIVE,
	})

	if err := r.repo.CreateKey(ctx, k, v); err != nil {
		return nil, errors.Wrap(ctx, op, err)
	}

	return k, nil
}

func (r *keyOrchestrator) ReadKey(ctx context.Context, _ string) (*key.Key, error) {
	return nil, errors.New(ctx, "service.(keyOrchestrator).ReadKey", errors.CodeNotImplemented,
		"ReadKey not yet implemented")
}

func (r *keyOrchestrator) ListKeys(ctx context.Context) ([]*key.Key, error) {
	return nil, errors.New(ctx, "service.(keyOrchestrator).ListKeys", errors.CodeNotImplemented,
		"ListKeys not yet implemented")
}

func (r *keyOrchestrator) DeleteKey(ctx context.Context, _ string) error {
	return errors.New(ctx, "service.(keyOrchestrator).DeleteKey", errors.CodeNotImplemented,
		"DeleteKey not yet implemented")
}

func (r *keyOrchestrator) GetKeyWithMaterial(ctx context.Context, _ string, _ uint32) (*key.Key, *key.Version, error) {
	return nil, nil, errors.New(ctx, "service.(keyOrchestrator).GetKeyWithMaterial", errors.CodeNotImplemented,
		"GetKeyWithMaterial not yet implemented")
}

func (r *keyOrchestrator) RotateKey(ctx context.Context, _ string) (*key.Key, error) {
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

func (r *keyOrchestrator) ImportKey(ctx context.Context, _ core.ImportKeySpec) (*key.Key, error) {
	return nil, errors.New(ctx, "service.(keyOrchestrator).ImportKey", errors.CodeNotImplemented,
		"ImportKey not yet implemented")
}

func (r *keyOrchestrator) UpdateKeyPolicy(ctx context.Context, _ string, _ string) error {
	return errors.New(ctx, "service.(keyOrchestrator).UpdateKeyPolicy", errors.CodeNotImplemented,
		"UpdateKeyPolicy not yet implemented")
}

// Compile-time assertion: keyOrchestrator implements KeyOrchestrator.
var _ KeyOrchestrator = (*keyOrchestrator)(nil)
