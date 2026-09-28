package discogrpc

import (
	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/template"
)

// AlgorithmDiscoveryHandler serves services.AlgorithmDiscoveryService — the
// read-only catalogue of algorithm templates and the scopes they belong to.
//
// Every RPC is a pure read of the template registry, which is process-wide and
// immutable after startup. The handler therefore needs no key repository, no
// policy engine and no storage of any kind: a discovery-only server is the
// cheapest deployment in the API.
//
// Immutable after construction, safe for concurrent use.
type AlgorithmDiscoveryHandler struct {
	templates template.RegistryFactory
	servicespb.UnimplementedAlgorithmDiscoveryServiceServer
}

var _ servicespb.AlgorithmDiscoveryServiceServer = (*AlgorithmDiscoveryHandler)(nil)

const algorithmDiscoveryHandlerOp = engerr.Op("grpc.(AlgorithmDiscoveryHandler)")
