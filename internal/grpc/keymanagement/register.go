// Package keygrpc serves services.KeyManagementService.
//
// Its dependency is the key orchestrator, which by construction reaches every
// domain port (keys, policy, providers, templates) because key creation
// genuinely consults all of them. So unlike policygrpc this package is not
// cheap to deploy alone — that is a property of the orchestrator, not of the
// wiring, and it is the honest answer rather than something the package split
// can remove.
package keygrpc

import (
	"context"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
	"github.com/agile-crypto/citius-server/internal/service"

	"google.golang.org/grpc"
)

const newOp engerr.Op = "grpc/keymanagement.New"

// New builds the handler from the per-request key orchestrator factory and the
// authorization checks its RPCs perform. newKeys must not be nil.
//
// authorizeKey and authorizePolicy must not be nil either: pass
// authz.KeyName() / authz.PolicyName() to enforce authorization, or a closure
// returning nil to run without it. Making that the wiring's decision keeps the
// disabled case out of every RPC.
//
// A nil argument returns CodeInvalidArgument.
func New(ctx context.Context, newKeys service.KeyOrchestratorFactory, authorizeKey grpcstatus.AuthorizeKeyName, authorizePolicy grpcstatus.AuthorizePolicyName) (*KeyManagementHandler, error) {
	switch {
	case newKeys == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "key orchestrator factory is required")
	case authorizeKey == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "key authorization check is required; pass a check that always returns nil to run without authorization")
	case authorizePolicy == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "policy authorization check is required; pass a check that always returns nil to run without authorization")
	}
	return &KeyManagementHandler{keys: newKeys, authorizeKey: authorizeKey, authorizePolicy: authorizePolicy}, nil
}

// Register registers the service on reg.
func Register(reg grpc.ServiceRegistrar, h *KeyManagementHandler) {
	servicespb.RegisterKeyManagementServiceServer(reg, h)
}
