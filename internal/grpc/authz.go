package grpc

import (
	"context"

	citiusauth "github.com/agile-crypto/citius-server/internal/auth"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
)

// authorizeKeyName runs the per-resource glob check for a key name and
// translates the upstream Forbidden / Unauthenticated error into the
// service's *Error vocabulary so ToStatusError maps to the correct gRPC
// code (PermissionDenied / Unauthenticated).
//
// Returns nil when auth is disabled (no claims attached) or the caller's
// allow-list permits name.
func authorizeKeyName(ctx context.Context, op engerr.Op, name string) error {
	return translateAuthzError(ctx, op, citiusauth.AuthorizeKey(ctx, name))
}

// authorizePolicyName mirrors authorizeKeyName for crypto-policy resources.
func authorizePolicyName(ctx context.Context, op engerr.Op, name string) error {
	return translateAuthzError(ctx, op, citiusauth.AuthorizePolicy(ctx, name))
}

func translateAuthzError(ctx context.Context, op engerr.Op, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case citiusauth.IsForbidden(err):
		return engerr.New(ctx, op, engerr.CodePolicyViolation, err.Error())
	case citiusauth.IsUnauthenticated(err):
		return engerr.New(ctx, op, engerr.CodeUnauthenticated, err.Error())
	default:
		return engerr.Wrap(ctx, op, err)
	}
}
