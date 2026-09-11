// Package discogrpc serves services.AlgorithmDiscoveryService.
//
// Every RPC is a read of the template catalogue, so this package reaches
// internal/template and nothing else. With an in-process catalogue that makes a
// discovery-only server nearly dependency-free; once the catalogue moves to
// SQL it gains a database and its failure modes, but no additional domain.
package discogrpc

import (
	"context"

	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-server/internal/template"

	"google.golang.org/grpc"
)

const newOp engerr.Op = "grpc/discovery.New"

// New builds the handler from the per-request template registry factory.
// newTemplates must not be nil.
//
// A nil argument returns CodeInvalidArgument.
func New(ctx context.Context, newTemplates template.RegistryFactory) (*AlgorithmDiscoveryHandler, error) {
	if newTemplates == nil {
		return nil, engerr.New(ctx, newOp, engerr.CodeInvalidArgument, "template registry factory is required")
	}
	return &AlgorithmDiscoveryHandler{templates: newTemplates}, nil
}

// Register registers the service on reg.
func Register(reg grpc.ServiceRegistrar, h *AlgorithmDiscoveryHandler) {
	servicespb.RegisterAlgorithmDiscoveryServiceServer(reg, h)
}
