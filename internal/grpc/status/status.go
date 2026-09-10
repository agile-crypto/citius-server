// Package status holds what every gRPC handler package needs and none of them
// owns: the domain-error-to-status mapping, and the *types* of the
// per-resource authorization checks.
//
// It deliberately holds no authorization *implementation*. The checks are
// declared here as function types so a handler can name one as a field, and
// they are supplied by the wiring — from internal/grpc/authz when auth is
// enabled, and as an always-allow closure when it is not. That is what keeps
// internal/auth, and the OIDC machinery behind it, out of the dependency graph
// of a deployment that does not use it.
//
// Its only dependency is internal/errors, so importing it from a policy-only
// server costs nothing beyond what that server already links.
package status

import (
	"context"
	stderrors "errors"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	engerr "github.com/agile-crypto/citius-server/internal/errors"
)

// ToStatusError converts a domain error to a gRPC status error, returning nil
// when err is nil. The code mapping comes from engerr.GRPCCode, so the switch
// table is not duplicated here.
//
// Note this mapping is many-to-one and therefore lossy: CodeKeyNotFound,
// CodePolicyNotFound and CodeTemplateNotFound all become codes.NotFound, and Op
// is dropped. That is right for the north-bound API and not sufficient for an
// internal transport — a remote adapter reconstructing a domain error needs the
// proto error detail carrying Code and Op.
func ToStatusError(err error) error {
	if err == nil {
		return nil
	}
	var e *engerr.Error
	if stderrors.As(err, &e) {
		return grpcstatus.Error(engerr.GRPCCode(err), e.Message)
	}
	return grpcstatus.Error(codes.Internal, err.Error())
}

// AuthorizeKeyName checks whether the caller may act on the named key,
// returning nil when it may. Implementations must return an error already in
// the domain vocabulary — CodePolicyViolation for a forbidden caller,
// CodeUnauthenticated for an unauthenticated one — so ToStatusError maps it to
// PermissionDenied or Unauthenticated.
//
// A handler always calls its check; the value must not be nil. A deployment
// that runs without per-resource authorization supplies a check that always
// returns nil, so "authorization is disabled" is a decision expressed once in
// the wiring rather than a branch in every RPC.
type AuthorizeKeyName func(ctx context.Context, op engerr.Op, name string) error

// AuthorizePolicyName mirrors AuthorizeKeyName for crypto-policy resources,
// under the same contract: never nil, and always-allow when the deployment
// disables authorization.
type AuthorizePolicyName func(ctx context.Context, op engerr.Op, name string) error
