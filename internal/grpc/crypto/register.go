// Package cryptogrpc serves services.CryptoService — the one-shot data-plane
// RPCs that operate with an existing key.
//
// One package per proto service, with no exception: sign/verify, key
// establishment and multi-part streaming all reach the crypto orchestrator, but
// they do not have the same dependencies (key establishment also manages key
// material; streaming will hold long-lived session state), and a package whose
// members need different things cannot state its own requirements.
//
// The proto-to-domain scope-parameter mapping these services share belongs in a
// helper package imported by each, not in a package that merges them.
package cryptogrpc

import (
	"context"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/service"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"

	"google.golang.org/grpc"
)

const newOp engerr.Op = "grpc/crypto.New"

// New builds the handler from the per-request crypto orchestrator factory and
// the authorization checks its RPCs perform: authorizeKey for RPCs on a
// stored key, authorizePolicy for VerifyWithPublicKey, which names a policy
// instead. newCrypto must not be nil.
//
// authorizeKey and authorizePolicy must not be nil either: pass
// authz.KeyName() / authz.PolicyName() to enforce authorization, or a closure
// returning nil to run without it. Making that the wiring's decision keeps the
// disabled case out of every RPC.
//
// A nil argument returns CodeInvalidArgument.
func New(ctx context.Context, newCrypto service.CryptoOrchestratorFactory, authorizeKey grpcstatus.AuthorizeKeyName, authorizePolicy grpcstatus.AuthorizePolicyName) (*CryptoHandler, error) {
	switch {
	case newCrypto == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "crypto orchestrator factory is required")
	case authorizeKey == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "key authorization check is required; pass a check that always returns nil to run without authorization")
	case authorizePolicy == nil:
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "policy authorization check is required; pass a check that always returns nil to run without authorization")
	}
	return &CryptoHandler{crypto: newCrypto, authorizeKey: authorizeKey, authorizePolicy: authorizePolicy}, nil
}

// Register registers the service on reg.
func Register(reg grpc.ServiceRegistrar, h *CryptoHandler) {
	servicespb.RegisterCryptoServiceServer(reg, h)
}
