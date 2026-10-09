package policygrpc

import (
	"context"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
)

// CryptoPolicyHandler serves services.CryptoPolicyService — CRUD over crypto
// policy documents plus the evaluation RPCs.
//
// It depends only on a PolicyEngineFactory — the whole reason a policy-only
// deployment is possible. Immutable after construction, safe for concurrent
// use.
//
// The authorization check is supplied by the wiring — an always-allow closure
// when the deployment runs without authorization — which is why this package
// does not import internal/auth.
type CryptoPolicyHandler struct {
	policy          policy.EngineFactory
	authorizePolicy grpcstatus.AuthorizePolicyName
	servicespb.UnimplementedCryptoPolicyServiceServer
}

var _ servicespb.CryptoPolicyServiceServer = (*CryptoPolicyHandler)(nil)

const cryptoPolicyHandlerOp = engerr.Op("grpc.(CryptoPolicyHandler)")

// CreateCryptoPolicy handles the CreateCryptoPolicy RPC.
//
//	messages.CreateCryptoPolicyRequest.name            => policy.Policy.Name()/PublicID()
//	messages.CreateCryptoPolicyRequest.policy_document => policy.Policy.RulesJSON()
func (h *CryptoPolicyHandler) CreateCryptoPolicy(ctx context.Context, req *messagespb.CreateCryptoPolicyRequest) (*messagespb.CreateCryptoPolicyResponse, error) {
	const createOp engerr.Op = cryptoPolicyHandlerOp + ".CreateCryptoPolicy"

	name := req.GetName()
	if name == "" {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, createOp, engerr.CodeInvalidArgument, "name is required"))
	}
	if err := h.authorizePolicy(ctx, createOp, name); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}
	if err := checkFormat(ctx, createOp, req.GetFormat()); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	engine, err := h.policy(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, createOp, err))
	}

	p := policy.NewPolicy(name, name, []byte(req.GetPolicyDocument()))
	created, err := engine.CreatePolicy(ctx, p)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, createOp, err))
	}

	return &messagespb.CreateCryptoPolicyResponse{
		Success: true,
		Message: "policy created",
		Version: created.Version(),
	}, nil
}

// ReadCryptoPolicy handles the ReadCryptoPolicy RPC.
func (h *CryptoPolicyHandler) ReadCryptoPolicy(ctx context.Context, req *messagespb.ReadCryptoPolicyRequest) (*messagespb.ReadCryptoPolicyResponse, error) {
	const readOp engerr.Op = cryptoPolicyHandlerOp + ".ReadCryptoPolicy"

	name := req.GetName()
	if name == "" {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, readOp, engerr.CodeInvalidArgument, "name is required"))
	}
	if err := h.authorizePolicy(ctx, readOp, name); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	engine, err := h.policy(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, readOp, err))
	}

	p, err := engine.GetPolicy(ctx, name)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, readOp, err))
	}

	return &messagespb.ReadCryptoPolicyResponse{
		Name:           p.Name(),
		PolicyDocument: string(p.RulesJSON()),
		Format:         policyFormatJSON,
		Version:        p.Version(),
		CreatedAt:      p.CreateTime(),
		UpdatedAt:      p.UpdateTime(),
	}, nil
}

// DeleteCryptoPolicy handles the DeleteCryptoPolicy RPC.
func (h *CryptoPolicyHandler) DeleteCryptoPolicy(ctx context.Context, req *messagespb.DeleteCryptoPolicyRequest) (*messagespb.DeleteCryptoPolicyResponse, error) {
	return h.UnimplementedCryptoPolicyServiceServer.DeleteCryptoPolicy(ctx, req)
}

// UpdateCryptoPolicy handles the UpdateCryptoPolicy RPC. The document is
// replaced wholesale — there are no merge semantics.
//
// expected_version is checked by the engine, not atomically with the write:
// the stored version is read and the new policy written in two store calls,
// so two concurrent updates with the same expected_version can both succeed
// and the later one wins (see policy.Manager.UpdatePolicy). A stale
// expected_version is still refused.
func (h *CryptoPolicyHandler) UpdateCryptoPolicy(ctx context.Context, req *messagespb.UpdateCryptoPolicyRequest) (*messagespb.UpdateCryptoPolicyResponse, error) {
	const updateOp engerr.Op = cryptoPolicyHandlerOp + ".UpdateCryptoPolicy"

	name := req.GetName()
	if name == "" {
		return nil, grpcstatus.ToStatusError(engerr.New(ctx, updateOp, engerr.CodeInvalidArgument, "name is required"))
	}
	if err := h.authorizePolicy(ctx, updateOp, name); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}
	if err := checkFormat(ctx, updateOp, req.GetFormat()); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	engine, err := h.policy(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, updateOp, err))
	}

	p := policy.NewPolicy(name, name, []byte(req.GetPolicyDocument()))
	updated, err := engine.UpdatePolicy(ctx, p, req.GetExpectedVersion())
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, updateOp, err))
	}

	return &messagespb.UpdateCryptoPolicyResponse{
		Success: true,
		Message: "policy updated",
		Version: updated.Version(),
	}, nil
}

// policyFormatJSON is the only policy document format the server reads: the
// rules evaluator parses JSON.
const policyFormatJSON = "json"

// checkFormat rejects a policy document format the server cannot read. An
// empty format means the server default, JSON.
func checkFormat(ctx context.Context, op engerr.Op, format string) error {
	if format == "" || format == policyFormatJSON {
		return nil
	}
	return engerr.New(ctx, op, engerr.CodeInvalidArgument,
		"unsupported policy format %q: only %q is supported", format, policyFormatJSON)
}

// ListCryptoPolicies handles the ListCryptoPolicies RPC.
func (h *CryptoPolicyHandler) ListCryptoPolicies(ctx context.Context, req *messagespb.ListCryptoPoliciesRequest) (*messagespb.ListCryptoPoliciesResponse, error) {
	return h.UnimplementedCryptoPolicyServiceServer.ListCryptoPolicies(ctx, req)
}

// EvaluatePolicy handles the EvaluatePolicy RPC: a dry-run of the policy rules
// against a proposed operation, with no side effects.
func (h *CryptoPolicyHandler) EvaluatePolicy(ctx context.Context, req *messagespb.EvaluatePolicyRequest) (*messagespb.EvaluatePolicyResponse, error) {
	return h.UnimplementedCryptoPolicyServiceServer.EvaluatePolicy(ctx, req)
}

// BatchEvaluatePolicy handles the BatchEvaluatePolicy RPC — EvaluatePolicy over
// many proposed operations in one round trip. Per-item failures are reported
// in the response, not as an RPC error.
func (h *CryptoPolicyHandler) BatchEvaluatePolicy(ctx context.Context, req *messagespb.BatchEvaluatePolicyRequest) (*messagespb.BatchEvaluatePolicyResponse, error) {
	return h.UnimplementedCryptoPolicyServiceServer.BatchEvaluatePolicy(ctx, req)
}
