package keygrpc

import (
	"context"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	core "github.com/agile-crypto/citius-core"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/service"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
)

// KeyManagementHandler serves services.KeyManagementService — the key lifecycle.
//
// One handler per proto service: each is registered independently on the gRPC
// server, depends only on the capability its RPCs actually use, and can be
// tested with a fake supplying just that capability.
//
// Immutable after construction and safe for concurrent use; all per-request
// state lives in the orchestrator it obtains from keys.
//
// The authorization checks are supplied by the wiring — always-allow closures
// when the deployment runs without authorization — which is why this package
// does not import internal/auth.
type KeyManagementHandler struct {
	keys            service.KeyOrchestratorFactory
	authorizeKey    grpcstatus.AuthorizeKeyName
	authorizePolicy grpcstatus.AuthorizePolicyName
	servicespb.UnimplementedKeyManagementServiceServer
}

var _ servicespb.KeyManagementServiceServer = (*KeyManagementHandler)(nil)

const keyManagementHandlerOp = engerr.Op("grpc.(KeyManagementHandler)")

// CreateKey handles the CreateKey RPC.
//
// Proto mapping:
//
//	messages.CreateKeyRequest.name        => core.KeyCreationSpec.Name
//	messages.CreateKeyRequest.policy      => core.KeyCreationSpec.PolicyID
//	messages.CreateKeyRequest.provider_id => core.KeyCreationSpec.ProviderInstanceID
//	messages.CreateKeyRequest.template_id => core.KeyCreationSpec.TemplateID (oneof)
//	messages.CreateKeyRequest.scope_spec  => core.KeyCreationSpec.ScopeSpecification (oneof)
func (h *KeyManagementHandler) CreateKey(ctx context.Context, req *messagespb.CreateKeyRequest) (*messagespb.CreateKeyResponse, error) {
	const createOp engerr.Op = keyManagementHandlerOp + ".CreateKey"

	if err := h.authorizeKey(ctx, createOp, req.GetName()); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}
	if req.GetPolicy() != "" {
		if err := h.authorizePolicy(ctx, createOp, req.GetPolicy()); err != nil {
			return nil, grpcstatus.ToStatusError(err)
		}
	}

	keys, err := h.keys(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, createOp, err))
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
			return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, createOp, err0, engerr.WithMessage("invalid scope_spec")))
		}
		spec.ScopeSpecification = scopeSpec
	}

	md, err := keys.CreateKey(ctx, spec)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, createOp, err))
	}

	return &messagespb.CreateKeyResponse{
		Success: true,
		KeyMetadata: &messagespb.KeyMetadata{
			Name:           md.Name,
			Version:        md.Version,
			Policy:         md.Policy,
			KeyId:          md.KeyID,
			TemplateId:     md.TemplateID,
			Provider:       md.Provider,
			LifecycleState: md.LifecycleState,
		},
	}, nil
}

// ReadKey handles the ReadKey RPC. A zero version means "latest".
func (h *KeyManagementHandler) ReadKey(ctx context.Context, req *messagespb.ReadKeyRequest) (*messagespb.ReadKeyResponse, error) {
	const readOp engerr.Op = keyManagementHandlerOp + ".ReadKey"

	if err := h.authorizeKey(ctx, readOp, req.GetName()); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	keys, err := h.keys(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, readOp, err))
	}

	md, err := keys.ReadKey(ctx, req.GetName(), req.GetVersion())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, readOp, err))
	}

	return &messagespb.ReadKeyResponse{
		KeyMetadata: &messagespb.KeyMetadata{
			Name:           md.Name,
			Version:        md.Version,
			Policy:         md.Policy,
			KeyId:          md.KeyID,
			TemplateId:     md.TemplateID,
			Provider:       md.Provider,
			LifecycleState: md.LifecycleState,
		},
	}, nil
}

// ListKeys handles the ListKeys RPC.
func (h *KeyManagementHandler) ListKeys(ctx context.Context, req *messagespb.ListKeysRequest) (*messagespb.ListKeysResponse, error) {
	return h.UnimplementedKeyManagementServiceServer.ListKeys(ctx, req)
}

// DeleteKey handles the DeleteKey RPC.
func (h *KeyManagementHandler) DeleteKey(ctx context.Context, req *messagespb.DeleteKeyRequest) (*messagespb.DeleteKeyResponse, error) {
	return h.UnimplementedKeyManagementServiceServer.DeleteKey(ctx, req)
}

// RotateKey handles the RotateKey RPC.
func (h *KeyManagementHandler) RotateKey(ctx context.Context, req *messagespb.RotateKeyRequest) (*messagespb.RotateKeyResponse, error) {
	return h.UnimplementedKeyManagementServiceServer.RotateKey(ctx, req)
}

// TransformKey handles the TransformKey RPC: re-scoping an existing key onto a
// new template/scope specification, optionally retaining the key bytes.
func (h *KeyManagementHandler) TransformKey(ctx context.Context, req *messagespb.TransformKeyRequest) (*messagespb.TransformKeyResponse, error) {
	const op engerr.Op = keyManagementHandlerOp + ".TransformKey"

	keyName := req.GetName()
	if err := h.authorizeKey(ctx, op, keyName); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	keys, err := h.keys(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}

	if req.ScopeSpec == nil {
		err := engerr.New(ctx, op, engerr.CodeInvalidArgument, "scope_spec is required with at least a scope set")
		return nil, grpcstatus.ToStatusError(err)
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
			return nil, grpcstatus.ToStatusError(err0)
		}
		transformSpec.ScopeSpecification = scopeSpec
	}

	md, err := keys.TransformKey(ctx, transformSpec)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}
	mdProto, err := md.ToProto(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, op, err))
	}

	return &messagespb.TransformKeyResponse{
		Success:     true,
		KeyMetadata: mdProto,
	}, nil
}

// UpdateKeyPolicy handles the UpdateKeyPolicy RPC.
func (h *KeyManagementHandler) UpdateKeyPolicy(ctx context.Context, req *messagespb.UpdateKeyPolicyRequest) (*messagespb.UpdateKeyPolicyResponse, error) {
	return h.UnimplementedKeyManagementServiceServer.UpdateKeyPolicy(ctx, req)
}

// MigrateKey handles the MigrateKey RPC.
func (h *KeyManagementHandler) MigrateKey(ctx context.Context, req *messagespb.MigrateKeyRequest) (*messagespb.MigrateKeyResponse, error) {
	return h.UnimplementedKeyManagementServiceServer.MigrateKey(ctx, req)
}

// ValidateKeyOperation handles the ValidateKeyOperation RPC.
func (h *KeyManagementHandler) ValidateKeyOperation(ctx context.Context, req *messagespb.ValidateKeyOperationRequest) (*messagespb.ValidateKeyOperationResponse, error) {
	return h.UnimplementedKeyManagementServiceServer.ValidateKeyOperation(ctx, req)
}

// ExportKey handles the ExportKey RPC.
func (h *KeyManagementHandler) ExportKey(ctx context.Context, req *messagespb.ExportKeyRequest) (*messagespb.ExportKeyResponse, error) {
	return h.UnimplementedKeyManagementServiceServer.ExportKey(ctx, req)
}

// ImportKey handles the ImportKey RPC.
func (h *KeyManagementHandler) ImportKey(ctx context.Context, req *messagespb.ImportKeyRequest) (*messagespb.ImportKeyResponse, error) {
	return h.UnimplementedKeyManagementServiceServer.ImportKey(ctx, req)
}
