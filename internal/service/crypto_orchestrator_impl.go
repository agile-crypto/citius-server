package service

import (
	"context"

	providerpb "github.ibm.com/citius/citius-server/gen/go/provider"
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
	keyReader key.Reader
	policy    policy.Engine
	providers provider.Registry
	templates template.Registry
}

// NewCryptoOrchestrator creates a new CryptoOrchestrator.
// All five dependencies are required; returns an error if any is nil.
func NewCryptoOrchestrator(
	s storage.Storage,
	kr key.Reader,
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
	if kr == nil {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument,
			"key reader must not be nil")
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
		keyReader: kr,
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
	if req.KeyName == "" {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"KeyPublicID must not be empty")
	}
	if len(req.Payload) == 0 {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"Payload must not be empty")
	}

	// 2. Load the key aggregate and apply the protecting-operation lifecycle rule.
	//    Sign creates new protected data, so only ACTIVE keys are permitted.
	k, err := o.keyReader.GetKeyByName(ctx, req.KeyName)
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}
	if encErr := k.CanPerformOriginatingCrypto(); encErr != nil {
		return crypto.SignResult{}, errors.New(ctx, op, errors.CodeFailedPrecondition, encErr.Error())
	}

	// 3a. Fetch the current version's material.
	kv, err := o.keyReader.GetCurrentVersion(ctx, k.GetPublicId())
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 4. Validate operation against the key's attached policy.
	policyID := k.GetPolicyId()
	templateID := kv.GetTemplateId()
	err = o.policy.ValidateOperation(ctx, policyID, core.OperationSign, templateID, "")
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 5. Fetch the provider that created this key version.
	prov, err := o.providers.Get(ctx, kv.GetProviderId())
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 6. Resolve template → *types.AlgorithmDetails for provider dispatch.
	tmpl, err := o.templates.Get(ctx, templateID)
	if err != nil {
		return crypto.SignResult{}, errors.Wrap(ctx, op, err)
	}

	// 6a. Validate that the caller's scope_params match the key's declared scope.
	if err = validateSignatureScopeParams(ctx, op, k, req.SignatureScopeFields); err != nil {
		return crypto.SignResult{}, err
	}

	// 6b. Unmarshal stored GenerateKeyResponse to extract private key material.
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
		KeyName:      req.KeyName,
		KeyVersion:   kv.GetVersion(),
		Algorithm:    templateID,
		ProviderName: prov.Name(),
		Output:       signResp.GetOutput(),
	}, nil
}

func (o *cryptoOrchestrator) Verify(ctx context.Context, req crypto.VerifyRequest) (crypto.VerifyResult, error) {
	const op errors.Op = "service.(cryptoOrchestrator).Verify"

	// 1. Validate request.
	if req.KeyName == "" {
		return crypto.VerifyResult{}, errors.New(ctx, op, errors.CodeInvalidArgument,
			"KeyPublicID must not be empty")
	}

	// 2. Load the key aggregate and apply the processing-operation lifecycle rule.
	//    Verify processes existing signatures, so ACTIVE, SUSPENDED, and
	//    DEACTIVATED ("legacy") keys are permitted.
	k, err := o.keyReader.GetKeyByName(ctx, req.KeyName)
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}
	if decErr := k.CanPerformReceivingCrypto(); decErr != nil {
		return crypto.VerifyResult{}, errors.New(ctx, op, errors.CodeFailedPrecondition, decErr.Error())
	}

	// 2a. Fetch the right version's material (includes public key bytes).
	kv, err := o.keyReader.GetVersion(ctx, k.GetPublicId(), req.KeyVersion)
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

	// 5. Resolve template => *types.AlgorithmDetails for provider dispatch.
	tmpl, err := o.templates.Get(ctx, templateID)
	if err != nil {
		return crypto.VerifyResult{}, errors.Wrap(ctx, op, err)
	}

	// 5a. Validate that the caller's scope_params match the key's declared scope.
	if err = validateSignatureScopeParams(ctx, op, k, req.SignatureScopeFields); err != nil {
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
		Output:      req.Output,
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
		KeyName:      req.KeyName,
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

// validateSignatureScopeParams validates that the caller's scope_params
// are compatible with the key's declared ScopeSpecification.
//
// The orchestrator handles:
//  1. Vendor short-circuit (vendor context bypasses standard scope matching)
//  2. Proto oneof arm → core.Scope mapping
//  3. Delegating semantic validation to core.ValidateSignatureScope
//  4. Wrapping core errors with ctx/op/code
//
// The proto oneof at the API boundary guarantees at-most-one variant.
// If none is set, callerScope maps to "" and core rejects it.
func validateSignatureScopeParams(
	ctx context.Context,
	op errors.Op,
	k *key.Key,
	sf crypto.SignatureScopeFields,
) error {
	// 1. Vendor context bypasses standard scope matching.
	if sf.VendorContext != nil {
		return nil
	}

	// 2. Map proto oneof arm => core.Scope.
	//    If no arm is set (all nil), callerScope is "",
	//    which core.ValidateSignatureScope rejects.
	var callerScope core.Scope
	switch {
	case sf.NoContext != nil:
		callerScope = core.SignatureScopeStandard
	case sf.DomainContext != nil:
		callerScope = core.SignatureScopeWithContext
	}

	// 3. Deserialize the key's scope specification.
	keyScope, err := core.ParseScopeSpec(ctx, k.GetScopeSpecification())
	if err != nil {
		return errors.Wrap(ctx, op, err)
	}

	// 4. Delegate semantic validation to core.
	if err := core.ValidateSignatureScope(ctx, keyScope, callerScope); err != nil {
		return errors.Wrap(ctx, op, err)
	}
	return nil
}

// Compile-time assertion
var _ CryptoOrchestrator = (*cryptoOrchestrator)(nil)
