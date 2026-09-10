// Package policygrpc serves services.CryptoPolicyService.
//
// It is the smallest deployment in the API and the reason the handler packages
// are split at all: its import graph reaches internal/policy, the generated
// protos and internal/grpc/status, and nothing else — no key repository, no
// provider registry, no template catalogue, and no storage backend. A server
// built from this package alone links only what policy CRUD and evaluation
// genuinely need.
//
// That property is not self-maintaining. It holds only while nothing here
// imports a package outside that set, and it is meant to be enforced by an
// import-graph assertion in CI rather than by review.
//
// Handler bodies map proto to the policy engine and convert domain errors with
// internal/grpc/status.
package policygrpc

import (
	"context"

	servicespb "github.com/agile-crypto/citius-server/gen/go/api/services"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
	"github.com/agile-crypto/citius-server/internal/policy"

	"google.golang.org/grpc"
)

const newOp engerr.Op = "grpc/policy.New"

// New builds the handler from the per-request policy engine factory and the
// policy authorization check its RPCs perform. newPolicy must not be nil.
//
// authorizePolicy must not be nil either: pass authz.PolicyName() to enforce
// authorization, or a closure returning nil to run without it. Making that the
// wiring's decision keeps the disabled case out of every RPC.
//
// A nil argument returns CodeInvalidArgument.
func New(ctx context.Context, newPolicy policy.EngineFactory, authorizePolicy grpcstatus.AuthorizePolicyName) (*CryptoPolicyHandler, error) {
	switch {
	case newPolicy == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "policy engine factory is required")
	case authorizePolicy == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "policy authorization check is required; pass a check that always returns nil to run without authorization")
	}
	return &CryptoPolicyHandler{policy: newPolicy, authorizePolicy: authorizePolicy}, nil
}

// Register registers the service on reg. The composition root decides whether
// this service is exposed at all; a deployment that omits it never imports this
// package.
func Register(reg grpc.ServiceRegistrar, h *CryptoPolicyHandler) {
	servicespb.RegisterCryptoPolicyServiceServer(reg, h)
}
