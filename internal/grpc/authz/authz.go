// Package authz supplies the authorization checks a handler accepts, backed by
// the per-resource allow-lists in internal/auth.
//
// It exists so that internal/auth is imported by the wiring rather than by the
// handlers: a deployment that runs without authorization never references this
// package, and never links the OIDC machinery behind it. A deployment that does
// enable authorization builds the checks here and passes them to the handler
// constructors.
package authz

import (
	"context"

	citiusauth "github.com/agile-crypto/citius-server/internal/auth"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-server/internal/grpc/status"
)

// AuthorizeKeyName returns the check for key resources: the per-resource glob check from
// internal/auth, with its Forbidden / Unauthenticated errors translated into
// the domain error vocabulary.
//
// The returned check also allows the request when auth is disabled at the
// interceptor level (no claims attached to the context), which is a different
// condition from the handler having no check at all.
func AuthorizeKeyName() status.AuthorizeKeyName {
	return func(ctx context.Context, op engerr.Op, name string) error {
		return translate(ctx, op, citiusauth.AuthorizeKey(ctx, name))
	}
}

// AuthorizePolicyName mirrors AuthorizeKeyName for crypto-policy resources.
func AuthorizePolicyName() status.AuthorizePolicyName {
	return func(ctx context.Context, op engerr.Op, name string) error {
		return translate(ctx, op, citiusauth.AuthorizePolicy(ctx, name))
	}
}

func translate(ctx context.Context, op engerr.Op, err error) error {
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
