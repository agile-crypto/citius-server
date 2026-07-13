package grpc

import (
	"context"

	messagespb "github.ibm.com/citius/citius-server/gen/go/api/messages"
	servicespb "github.ibm.com/citius/citius-server/gen/go/api/services"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/crypto"
	engerr "github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/policy"
	"github.ibm.com/citius/citius-server/internal/service"
	"github.ibm.com/citius/citius-server/internal/storage"
)

// ScopeGateway is the per-request subset of *app.RequestScope used by the Handler.
// *app.RequestScope satisfies this interface via its Keys(), Crypto(), and Policy() methods.
type ScopeGateway interface {
	Keys() service.KeyOrchestrator
	Crypto() service.CryptoOrchestrator
	Policy() policy.Engine
}

// ServiceGateway abstracts app.Service for testability.
// Tests inject a mock directly; production code wraps *app.Service with an adapter.
type ServiceGateway interface {
	ForStorage(ctx context.Context, store storage.Storage) (ScopeGateway, error)
}

// Compile-time assertions: Handler implements all three generated server interfaces.
// This catches any method-signature drift between handler.go and the proto definitions.
var _ servicespb.CryptoServiceServer = (*Handler)(nil)
var _ servicespb.KeyManagementServiceServer = (*Handler)(nil)
var _ servicespb.CryptoPolicyServiceServer = (*Handler)(nil)

const handlerOp = engerr.Op("grpc.(Handler)")

// Handler translates gRPC requests into core calls via a ServiceGateway.
// It holds no mutable state after construction — safe for concurrent use.
type Handler struct {
	svc   ServiceGateway
	store func() storage.Storage // factory for per-request Storage; nil is allowed in tests
	servicespb.UnimplementedCryptoServiceServer
	servicespb.UnimplementedKeyManagementServiceServer
	servicespb.UnimplementedCryptoPolicyServiceServer
}

// New creates a Handler.
// storageFactory can be nil in tests that inject a mock service (getScope passes nil storage).
// In production, always supply a real storageFactory.
func New(svc ServiceGateway, storageFactory func() storage.Storage) *Handler {
	return &Handler{svc: svc, store: storageFactory}
}

// getScope calls ForStorage and returns the per-request scope.
func (h *Handler) getScope(ctx context.Context) (ScopeGateway, error) {
	const scopeOp engerr.Op = handlerOp + ".getScope"
	var store storage.Storage
	if h.store != nil {
		store = h.store()
	}
	scope, err := h.svc.ForStorage(ctx, store)
	if err != nil {
		return nil, engerr.Wrap(ctx, scopeOp, err)
	}
	return scope, nil
}

// CreateKey handles the CreateKey RPC.
//
// Proto mapping:
//
//	messages.CreateKeyRequest.name            => core.KeyCreationSpec.Name
//	messages.CreateKeyRequest.policy          => core.KeyCreationSpec.PolicyID
//	messages.CreateKeyRequest.provider_id     => core.KeyCreationSpec.ProviderInstanceID
//	messages.CreateKeyRequest.template_id     => core.KeyCreationSpec.TemplateID (oneof)
//	messages.CreateKeyRequest.scope_spec      => core.KeyCreationSpec.Scope (serialised, oneof)
func (h *Handler) CreateKey(ctx context.Context, req *messagespb.CreateKeyRequest) (*messagespb.CreateKeyResponse, error) {
	const createOp engerr.Op = handlerOp + ".CreateKey"

	if err := authorizeKeyName(ctx, createOp, req.GetName()); err != nil {
		return nil, ToStatusError(err)
	}
	if req.GetPolicy() != "" {
		if err := authorizePolicyName(ctx, createOp, req.GetPolicy()); err != nil {
			return nil, ToStatusError(err)
		}
	}

	scope, err := h.getScope(ctx)
	if err != nil {
		return nil, ToStatusError(err)
	}

	spec := core.KeyCreationSpec{
		Name:               req.GetName(),
		PolicyID:           req.GetPolicy(),
		ProviderInstanceID: req.GetProviderId(),
	}

	// Handle key_specification oneof: template_id XOR scope_spec.
	if req.TemplateId != nil {
		spec.TemplateID = *req.TemplateId
	}
	if req.ScopeSpec != nil {
		scopeSpec, err0 := core.ScopeSpecificationFromProto(ctx, req.ScopeSpec)
		if err0 != nil {
			return nil, ToStatusError(engerr.Wrap(ctx, createOp, err0, engerr.WithMessage("invalid scope_spec")))
		}
		spec.ScopeSpecification = scopeSpec
	}

	md, err := scope.Keys().CreateKey(ctx, spec)
	if err != nil {
		return nil, ToStatusError(engerr.Wrap(ctx, createOp, err))
	}

	return &messagespb.CreateKeyResponse{
		Success: true,
		KeyMetadata: &messagespb.KeyMetadata{
			Name:       md.Name,
			Version:    md.Version,
			Policy:     md.Policy,
			KeyId:      md.KeyID,
			TemplateId: md.TemplateID,
			Provider:   md.Provider,
		},
	}, nil
}

// ReadKey handles the ReadKey RPC.
//
// Proto mapping:
//
//	messages.ReadKeyRequest.name    => KeyOrchestrator.ReadKey(ctx, name, version)
//	messages.ReadKeyRequest.version => version (0 = latest)
func (h *Handler) ReadKey(ctx context.Context, req *messagespb.ReadKeyRequest) (*messagespb.ReadKeyResponse, error) {
	const readOp engerr.Op = handlerOp + ".ReadKey"

	if err := authorizeKeyName(ctx, readOp, req.GetName()); err != nil {
		return nil, ToStatusError(err)
	}

	scope, err := h.getScope(ctx)
	if err != nil {
		return nil, ToStatusError(err)
	}

	md, err := scope.Keys().ReadKey(ctx, req.GetName(), req.GetVersion())
	if err != nil {
		return nil, ToStatusError(engerr.Wrap(ctx, readOp, err))
	}

	return &messagespb.ReadKeyResponse{
		KeyMetadata: &messagespb.KeyMetadata{
			Name:       md.Name,
			Version:    md.Version,
			Policy:     md.Policy,
			KeyId:      md.KeyID,
			TemplateId: md.TemplateID,
			Provider:   md.Provider,
		},
	}, nil
}

// Sign handles the Sign RPC.
//
// Proto mapping:
//
//	messages.SignRequest.key_name     => crypto.SignRequest.KeyPublicID
//	messages.SignRequest.input        => crypto.SignRequest.Payload
//	messages.SignRequest.scope_params => crypto.SignRequest.{NoContext,DomainContext,VendorContext}
//	crypto.SignResult.Output          => messages.SignResponse.Metadata.ProviderOutput
func (h *Handler) Sign(ctx context.Context, req *messagespb.SignRequest) (*messagespb.SignResponse, error) {
	const signOp engerr.Op = handlerOp + ".Sign"

	if err := authorizeKeyName(ctx, signOp, req.GetKeyName()); err != nil {
		return nil, ToStatusError(err)
	}

	scope, err := h.getScope(ctx)
	if err != nil {
		return nil, ToStatusError(err)
	}

	signReq := crypto.SignRequest{
		KeyName: req.GetKeyName(),
		Payload: req.GetInput(),
	}
	extractSigningScopeParams(req.GetScopeParams(), &signReq)

	result, err := scope.Crypto().Sign(ctx, signReq)
	if err != nil {
		return nil, ToStatusError(engerr.Wrap(ctx, signOp, err))
	}

	// Wrap ProviderOutput into OperationMetadata.
	return &messagespb.SignResponse{
		Signature: result.Signature,
		Metadata: &messagespb.OperationMetadata{
			KeyVersion:     result.KeyVersion,
			ProviderOutput: result.Output,
			//TODO: Add user context and API version
		},
	}, nil
}

// Verify handles the Verify RPC.
//
// Proto mapping:
//
//	messages.VerifyRequest.key_name     => crypto.VerifyRequest.KeyPublicID
//	messages.VerifyRequest.input        => crypto.VerifyRequest.Payload
//	messages.VerifyRequest.signature    => crypto.VerifyRequest.Signature
//	messages.VerifyRequest.scope_params => crypto.VerifyRequest.{NoContext,DomainContext,VendorContext}
//	crypto.VerifyResult.Output          => messages.VerifyResponse.Metadata.ProviderOutput
//
// An invalid signature is NOT an error — it returns Valid: false with no error.
func (h *Handler) Verify(ctx context.Context, req *messagespb.VerifyRequest) (*messagespb.VerifyResponse, error) {
	const verifyOp engerr.Op = handlerOp + ".Verify"

	if err := authorizeKeyName(ctx, verifyOp, req.GetKeyName()); err != nil {
		return nil, ToStatusError(err)
	}

	scope, err := h.getScope(ctx)
	if err != nil {
		return nil, ToStatusError(err)
	}

	//TODO: Check API version in req.GetMetadata() and reject if unsupported.

	verifyReq := crypto.VerifyRequest{
		KeyName:    req.GetKeyName(),
		Payload:    req.GetInput(),
		Signature:  req.GetSignature(),
		KeyVersion: req.GetMetadata().GetKeyVersion(),
		Output:     req.GetMetadata().GetProviderOutput(),
	}
	extractVerifyScopeParams(req.GetScopeParams(), &verifyReq)

	result, err := scope.Crypto().Verify(ctx, verifyReq)
	if err != nil {
		return nil, ToStatusError(engerr.Wrap(ctx, verifyOp, err))
	}

	return &messagespb.VerifyResponse{
		Valid: result.Valid,
		Metadata: &messagespb.OperationMetadata{
			ProviderOutput: result.Output,
		},
	}, nil
}

// extractSigningScopeParams maps the proto scope_params oneof to Go pointer fields.
// The proto oneof interface (isSignRequest_ScopeParams) is unexported, so we accept any.
// Concrete wrapper types SignRequest_NoContext / _DomainContext / _VendorContext are exported.
func extractSigningScopeParams(sp any, req *crypto.SignRequest) {
	switch v := sp.(type) {
	case *messagespb.SignRequest_NoContext:
		req.NoContext = v.NoContext
	case *messagespb.SignRequest_DomainContext:
		req.DomainContext = v.DomainContext
	case *messagespb.SignRequest_VendorContext:
		req.VendorContext = v.VendorContext
	default:
		// nil or unrecognised variant — downstream validation will report the issue.
	}
}

// extractVerifyScopeParams maps the proto scope_params oneof for VerifyRequest.
// Same pattern as extractSigningScopeParams but uses VerifyRequest_* wrapper types.
func extractVerifyScopeParams(sp any, req *crypto.VerifyRequest) {
	switch v := sp.(type) {
	case *messagespb.VerifyRequest_NoContext:
		req.NoContext = v.NoContext
	case *messagespb.VerifyRequest_DomainContext:
		req.DomainContext = v.DomainContext
	case *messagespb.VerifyRequest_VendorContext:
		req.VendorContext = v.VendorContext
	default:
		// nil or unrecognised variant.
	}
}

// CreateCryptoPolicy handles the CreateCryptoPolicy RPC.
//
// Proto mapping:
//
//	messages.CreateCryptoPolicyRequest.name            => policy.Policy.Name() / PublicID()
//	messages.CreateCryptoPolicyRequest.policy_document => policy.Policy.RulesJSON() (bytes)
func (h *Handler) CreateCryptoPolicy(ctx context.Context, req *messagespb.CreateCryptoPolicyRequest) (*messagespb.CreateCryptoPolicyResponse, error) {
	const createOp engerr.Op = handlerOp + ".CreateCryptoPolicy"

	name := req.GetName()
	if name == "" {
		return nil, ToStatusError(engerr.New(ctx, createOp, engerr.CodeInvalidArgument, "name is required"))
	}
	if err := authorizePolicyName(ctx, createOp, name); err != nil {
		return nil, ToStatusError(err)
	}

	scope, err := h.getScope(ctx)
	if err != nil {
		return nil, ToStatusError(err)
	}

	p := policy.NewPolicy(name, name, []byte(req.GetPolicyDocument()))
	if _, err := scope.Policy().CreatePolicy(ctx, p); err != nil {
		return nil, ToStatusError(engerr.Wrap(ctx, createOp, err))
	}

	return &messagespb.CreateCryptoPolicyResponse{
		Success: true,
		Message: "policy created",
	}, nil
}

// ReadCryptoPolicy handles the ReadCryptoPolicy RPC.
//
// Proto mapping:
//
//	messages.ReadCryptoPolicyRequest.name => policy.Manager.GetPolicy(ctx, name)
//	policy.Policy.RulesJSON()             => messages.ReadCryptoPolicyResponse.policy_document
func (h *Handler) ReadCryptoPolicy(ctx context.Context, req *messagespb.ReadCryptoPolicyRequest) (*messagespb.ReadCryptoPolicyResponse, error) {
	const readOp engerr.Op = handlerOp + ".ReadCryptoPolicy"

	name := req.GetName()
	if name == "" {
		return nil, ToStatusError(engerr.New(ctx, readOp, engerr.CodeInvalidArgument, "name is required"))
	}
	if err := authorizePolicyName(ctx, readOp, name); err != nil {
		return nil, ToStatusError(err)
	}

	scope, err := h.getScope(ctx)
	if err != nil {
		return nil, ToStatusError(err)
	}

	p, err := scope.Policy().GetPolicy(ctx, name)
	if err != nil {
		return nil, ToStatusError(engerr.Wrap(ctx, readOp, err))
	}

	return &messagespb.ReadCryptoPolicyResponse{
		Name:           p.Name(),
		PolicyDocument: string(p.RulesJSON()),
	}, nil
}

// UpdateCryptoPolicy handles the UpdateCryptoPolicy RPC.
// Replaces the policy document entirely (no merge semantics).
//
// Proto mapping:
//
//	messages.UpdateCryptoPolicyRequest.name            => policy.Policy.Name()
//	messages.UpdateCryptoPolicyRequest.policy_document => policy.Policy.RulesJSON()
func (h *Handler) UpdateCryptoPolicy(ctx context.Context, req *messagespb.UpdateCryptoPolicyRequest) (*messagespb.UpdateCryptoPolicyResponse, error) {
	const updateOp engerr.Op = handlerOp + ".UpdateCryptoPolicy"

	name := req.GetName()
	if name == "" {
		return nil, ToStatusError(engerr.New(ctx, updateOp, engerr.CodeInvalidArgument, "name is required"))
	}
	if err := authorizePolicyName(ctx, updateOp, name); err != nil {
		return nil, ToStatusError(err)
	}

	scope, err := h.getScope(ctx)
	if err != nil {
		return nil, ToStatusError(err)
	}

	p := policy.NewPolicy(name, name, []byte(req.GetPolicyDocument()))
	if err := scope.Policy().UpdatePolicy(ctx, p); err != nil {
		return nil, ToStatusError(engerr.Wrap(ctx, updateOp, err))
	}

	return &messagespb.UpdateCryptoPolicyResponse{
		Success: true,
		Message: "policy updated",
	}, nil
}

// TransformKey handles the TransformKey RPC.
func (h *Handler) TransformKey(ctx context.Context, req *messagespb.TransformKeyRequest) (*messagespb.TransformKeyResponse, error) {
	const op = handlerOp + ".TransformKey"

	keyName := req.GetName()
	if err := authorizeKeyName(ctx, op, keyName); err != nil {
		return nil, ToStatusError(err)
	}

	scope, err := h.getScope(ctx)
	if err != nil {
		return nil, ToStatusError(err)
	}

	if req.ScopeSpec == nil {
		err := engerr.New(ctx, op, engerr.CodeInvalidArgument, "scope_spec is required with at least a scope set")
		return nil, ToStatusError(err)
	}

	transformSpec := service.TransformKeySpec{
		KeyName:     keyName,
		RetainBytes: req.GetRetainKeyBytes(),
		TemplateID:  req.GetTemplateId(), // default to empty; will be set below if present in request
	}

	if req.ScopeSpec != nil {
		scopeSpec, err0 := core.ScopeSpecificationFromProto(ctx, req.GetScopeSpec())
		if err0 != nil {
			err0 := engerr.Wrap(ctx, op, err0, engerr.WithMessage("invalid scope_spec"))
			return nil, ToStatusError(err0)
		}
		transformSpec.ScopeSpecification = scopeSpec
	}

	md, err := scope.Keys().TransformKey(ctx, transformSpec)
	if err != nil {
		return nil, ToStatusError(engerr.Wrap(ctx, op, err))
	}
	mdProto, err := md.ToProto(ctx)
	if err != nil {
		return nil, ToStatusError(engerr.Wrap(ctx, op, err))
	}

	return &messagespb.TransformKeyResponse{
		Success:     true,
		KeyMetadata: mdProto,
	}, nil
}
