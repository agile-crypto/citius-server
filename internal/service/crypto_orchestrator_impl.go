package service

import (
	"context"
	"encoding/json"
	"fmt"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
	types "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/crypto"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/key"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/provider"
	"github.ibm.com/citius/citius-server/internal/storage"
	"github.ibm.com/citius/citius-server/internal/template"
	"google.golang.org/protobuf/proto"
)

// cryptoOrchestrator implements CryptoOrchestrator.
// It coordinates key retrieval, policy validation, and provider dispatch
// for cryptographic operations.
type cryptoOrchestrator struct {
	store     storage.Storage
	keys      KeyOrchestrator
	policy    policy.Engine
	providers provider.Registry
	templates template.Registry
}

// NewCryptoOrchestrator creates a new CryptoOrchestrator.
// All five dependencies are required; returns an error if any is nil.
func NewCryptoOrchestrator(
	s storage.Storage,
	km KeyOrchestrator,
	pe policy.Engine,
	pr provider.Registry,
	tr template.Registry,
) (CryptoOrchestrator, error) {
	const op errors.Op = "service.NewCryptoOrchestrator"
	ctx := context.Background()

	if s == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"storage must not be nil")
	}
	if km == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"key orchestrator must not be nil")
	}
	if pe == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"policy engine must not be nil")
	}
	if pr == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"provider registry must not be nil")
	}
	if tr == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"template registry must not be nil")
	}

	return &cryptoOrchestrator{
		store:     s,
		keys:      km,
		policy:    pe,
		providers: pr,
		templates: tr,
	}, nil
}

// ---------------------------------------------------------------------------
// Sign / Verify
// ---------------------------------------------------------------------------

func (o *cryptoOrchestrator) Sign(ctx context.Context, req crypto.SignRequest) (crypto.SignResult, error) {
	const op errors.Op = "service.(cryptoOrchestrator).Sign"

	// 1. Validate request.
	if req.KeyPublicID == "" {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"KeyPublicID must not be empty")
	}
	if len(req.Payload) == 0 {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"Payload must not be empty")
	}

	// 2. Fetch key + material.
	//    lifecycle checks (IsTerminal, CanPerformCrypto) are
	//    enforced inside GetKeyWithMaterial — Sign does not duplicate them.
	k, kv, err := o.keys.GetKeyWithMaterial(ctx, req.KeyPublicID, 0) // 0 = latest
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 3. Validate operation against the key's attached policy.
	policyID := k.GetPolicyId()
	templateID := kv.GetTemplateId()
	err = o.policy.ValidateOperation(ctx, policyID, core.OperationSign, templateID, "")
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 4. Fetch the provider that created this key version.
	prov, err := o.providers.Get(ctx, kv.GetProviderId())
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 5. Resolve template → *types.AlgorithmDetails for provider dispatch.
	tmpl, err := o.templates.Get(ctx, templateID)
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 5a. Validate that the caller's scope_params match the key's declared scope.
	if err = validateSignatureScopeParams(ctx, op, k, signatureScopeParams{
		NoContext:     req.NoContext,
		DomainContext: req.DomainContext,
		VendorContext: req.VendorContext,
	}); err != nil {
		return crypto.SignResult{}, err
	}

	// 5b. Unmarshal stored GenerateKeyResponse to extract private key material.
	var genResp providerpb.GenerateKeyResponse
	if err = proto.Unmarshal(kv.GetKeyMaterial(), &genResp); err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 6. Build provider-level SignRequest with scope_params oneof.
	provReq := &providerpb.SignRequest{
		KeyMaterial: genResp.GetKeyMaterial(),
		Input:       req.Payload,
		Algorithm:   tmpl.GetAlgorithm(),
	}
	switch {
	case req.NoContext != nil:
		provReq.ScopeParams = &providerpb.SignRequest_NoContext{NoContext: req.NoContext}
	case req.DomainContext != nil:
		provReq.ScopeParams = &providerpb.SignRequest_DomainContext{DomainContext: req.DomainContext}
	case req.VendorContext != nil:
		provReq.ScopeParams = &providerpb.SignRequest_VendorContext{VendorContext: req.VendorContext}
	}

	// 7. Perform sign.
	signResp, err := prov.Sign(ctx, provReq)
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 8. Return result with metadata.
	return crypto.SignResult{
		Signature:    signResp.GetSignature(),
		KeyPublicID:  req.KeyPublicID,
		KeyVersionID: kv.GetPublicId(),
		Algorithm:    templateID,
		ProviderName: prov.Name(),
		Output:       signResp.GetOutput(),
	}, nil
}

func (o *cryptoOrchestrator) Verify(ctx context.Context, req crypto.VerifyRequest) (crypto.VerifyResult, error) {
	const op errors.Op = "service.(cryptoOrchestrator).Verify"

	// 1. Validate request.
	if req.KeyPublicID == "" {
		return crypto.VerifyResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"KeyPublicID must not be empty")
	}

	// 2. Fetch key + material (includes public key bytes for verification).
	//    Lifecycle checks (IsTerminal, CanPerformCrypto) are enforced inside
	//    GetKeyWithMaterial — Verify does not duplicate them.
	k, kv, err := o.keys.GetKeyWithMaterial(ctx, req.KeyPublicID, 0) // 0 = latest
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 3. Validate operation against the key's attached policy.
	policyID := k.GetPolicyId()
	templateID := kv.GetTemplateId()
	err = o.policy.ValidateOperation(ctx, policyID, core.OperationVerify, templateID, "")
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 4. Fetch the provider that created this key version.
	prov, err := o.providers.Get(ctx, kv.GetProviderId())
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 5. Resolve template → *types.AlgorithmDetails for provider dispatch.
	tmpl, err := o.templates.Get(ctx, templateID)
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 5a. Validate that the caller's scope_params match the key's declared scope.
	if err = validateSignatureScopeParams(ctx, op, k, signatureScopeParams{
		NoContext:     req.NoContext,
		DomainContext: req.DomainContext,
		VendorContext: req.VendorContext,
	}); err != nil {
		return crypto.VerifyResult{}, err
	}

	// 5b. Unmarshal stored GenerateKeyResponse to extract public key bytes.
	var genResp providerpb.GenerateKeyResponse
	if err = proto.Unmarshal(kv.GetKeyMaterial(), &genResp); err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 6. Build provider-level VerifyRequest with scope_params oneof.
	//    Verify receives the public key bytes, not the private key material.
	provReq := &providerpb.VerifyRequest{
		KeyMaterial: genResp.GetPublicKeyBytes(),
		Input:       req.Payload,
		Signature:   req.Signature,
		Algorithm:   tmpl.GetAlgorithm(),
	}
	switch {
	case req.NoContext != nil:
		provReq.ScopeParams = &providerpb.VerifyRequest_NoContext{NoContext: req.NoContext}
	case req.DomainContext != nil:
		provReq.ScopeParams = &providerpb.VerifyRequest_DomainContext{DomainContext: req.DomainContext}
	case req.VendorContext != nil:
		provReq.ScopeParams = &providerpb.VerifyRequest_VendorContext{VendorContext: req.VendorContext}
	}

	// 7. Perform verify.
	verifyResp, err := prov.Verify(ctx, provReq)
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 8. Return result — invalid signature is NOT an error.
	return crypto.VerifyResult{
		Valid:        verifyResp.GetValid(),
		KeyPublicID:  req.KeyPublicID,
		Algorithm:    templateID,
		ProviderName: prov.Name(),
		Output:       verifyResp.GetOutput(),
	}, nil
}

func (o *cryptoOrchestrator) Encrypt(ctx context.Context, _ crypto.EncryptRequest) (crypto.EncryptResult, error) {
	return crypto.EncryptResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).Encrypt", errors.CodeNotImplemented,
		"Encrypt is not yet implemented")
}

func (o *cryptoOrchestrator) Decrypt(ctx context.Context, _ crypto.DecryptRequest) (crypto.DecryptResult, error) {
	return crypto.DecryptResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).Decrypt", errors.CodeNotImplemented,
		"Decrypt is not yet implemented")
}

func (o *cryptoOrchestrator) WrapKey(ctx context.Context, _ crypto.WrapKeyRequest) (crypto.WrapKeyResult, error) {
	return crypto.WrapKeyResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).WrapKey", errors.CodeNotImplemented,
		"WrapKey is not yet implemented")
}

func (o *cryptoOrchestrator) UnwrapKey(ctx context.Context, _ crypto.UnwrapKeyRequest) (crypto.UnwrapKeyResult, error) {
	return crypto.UnwrapKeyResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).UnwrapKey", errors.CodeNotImplemented,
		"UnwrapKey is not yet implemented")
}

func (o *cryptoOrchestrator) DeriveKey(ctx context.Context, _ crypto.DeriveKeyRequest) (*key.Key, error) {
	return nil, errors.New(ctx,
		"service.(cryptoOrchestrator).DeriveKey", errors.CodeNotImplemented,
		"DeriveKey is not yet implemented")
}

func (o *cryptoOrchestrator) GenerateMAC(ctx context.Context, _ crypto.MacRequest) (crypto.MacResult, error) {
	return crypto.MacResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).GenerateMAC", errors.CodeNotImplemented,
		"GenerateMAC is not yet implemented")
}

func (o *cryptoOrchestrator) VerifyMAC(ctx context.Context, _ crypto.VerifyMacRequest) (crypto.VerifyMacResult, error) {
	return crypto.VerifyMacResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).VerifyMAC", errors.CodeNotImplemented,
		"VerifyMAC is not yet implemented")
}

func (o *cryptoOrchestrator) Digest(ctx context.Context, _ crypto.DigestRequest) (crypto.DigestResult, error) {
	return crypto.DigestResult{}, errors.New(ctx,
		"service.(cryptoOrchestrator).Digest", errors.CodeNotImplemented,
		"Digest is not yet implemented")
}

func (o *cryptoOrchestrator) GenerateRandom(ctx context.Context, _ int) ([]byte, error) {
	return nil, errors.New(ctx,
		"service.(cryptoOrchestrator).GenerateRandom", errors.CodeNotImplemented,
		"GenerateRandom is not yet implemented")
}

// ---------------------------------------------------------------------------
// Scope-param validation helpers
// ---------------------------------------------------------------------------

// signatureScopeParams groups the scope_params from a Sign or Verify request.
// Exactly one field must be non-nil, mirroring the scope_params oneof in proto.
type signatureScopeParams struct {
	NoContext     *types.NoParams
	DomainContext *types.SignatureDomainContext
	VendorContext *types.VendorSignatureContext
}

// validateSignatureScopeParams checks that:
//  1. Exactly one scope_params variant is set (enforcing the oneof contract).
//  2. The caller's scope_params match the key's declared ScopeSpecification.
//
// The key's ScopeSpecification (set at creation time or after transformation)
// is the authoritative source of truth. If the key was created with scope "standard", only
// NoContext is valid; if "with_context", only DomainContext is valid.
// VendorContext bypasses standard scope matching.
//
// Returns CodeInvalidArgument if the oneof contract is violated or the
// caller's scope_params do not align with the key's stored scope.
func validateSignatureScopeParams(
	ctx context.Context,
	op errors.Op,
	k *key.Key,
	sp signatureScopeParams,
) error {
	// 1. Exactly one scope_params must be set.
	count := 0
	if sp.NoContext != nil {
		count++
	}
	if sp.DomainContext != nil {
		count++
	}
	if sp.VendorContext != nil {
		count++
	}
	if count == 0 {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"exactly one scope_params must be set (no_context, domain_context, or vendor_context)")
	}
	if count > 1 {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			"exactly one scope_params must be set; multiple were provided")
	}

	// 2. Vendor context — no standard scope to validate.
	if sp.VendorContext != nil {
		return nil
	}

	// 3. Deserialize the key's stored scope specification.
	var keyScope core.ScopeSpec
	if err := json.Unmarshal(k.GetScopeSpecification(), &keyScope); err != nil {
		return errors.New(ctx, op, errors.CodeInternal,
			fmt.Sprintf("failed to deserialize key scope specification: %v", err))
	}

	// 4. Map the caller's scope_params variant to the expected scope.
	var callerScope core.Scope
	switch {
	case sp.NoContext != nil:
		callerScope = core.SignatureScopeStandard
	case sp.DomainContext != nil:
		callerScope = core.SignatureScopeWithContext
	}

	// 5. Validate caller's scope matches the key's declared scope.
	if keyScope.Scope != callerScope {
		return errors.New(ctx, op, errors.CodeInvalidArgument,
			fmt.Sprintf("scope_params %q does not match key scope %q",
				callerScope, keyScope.Scope))
	}
	return nil
}

// Compile-time assertion
var _ CryptoOrchestrator = (*cryptoOrchestrator)(nil)
