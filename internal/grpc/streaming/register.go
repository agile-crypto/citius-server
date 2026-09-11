// Package streamgrpc serves services.StreamingCryptoService — the multi-part
// (Init/Update/Final) and message-oriented forms of every operation in
// CryptoService.
//
// It is separate from cryptogrpc because its wiring is shaped differently, not
// merely because it is large. A multi-part session outlives the request that
// opened it, so it cannot come from a per-request factory the way an
// orchestrator does; it needs a long-lived, concurrency-safe session manager
// whose entries stay bound to the scope that opened them. And it is the only
// service in the API with a startup precondition: mixed local/remote multi-part
// sessions are out of scope, so the composition root must refuse to register
// this service unless every domain it touches is local.
//
// Both of those are properties of this service alone. Housing it with
// sign/verify would have hidden them behind a shared constructor.
package streamgrpc

import (
	"context"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/service"

	"google.golang.org/grpc"
)

const newOp engerr.Op = "grpc/streaming.New"

// New builds the handler from the per-request crypto orchestrator factory.
//
// TODO: it will also take the session manager once that core type exists; see
// StreamingCryptoHandler's doc comment. Until then the constructor deliberately
// takes only what can be honestly wired.
//
// A nil argument returns CodeInvalidArgument.
func New(ctx context.Context, newCrypto service.CryptoOrchestratorFactory) (*StreamingCryptoHandler, error) {
	if newCrypto == nil {
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "crypto orchestrator factory is required")
	}
	return &StreamingCryptoHandler{crypto: newCrypto}, nil
}

// Register registers the service on reg. Call the composition root's Validate
// first: this service must not be exposed in a mixed local/remote deployment.
func Register(reg grpc.ServiceRegistrar, h *StreamingCryptoHandler) {
	servicespb.RegisterStreamingCryptoServiceServer(reg, h)
}
