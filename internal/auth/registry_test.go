package auth_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	servicespb "github.ibm.com/citius/citius-server/gen/go/services"
	"github.ibm.com/citius/citius-server/internal/auth"
	"google.golang.org/grpc"
)

// TestPolicyRegistry_CoversEveryRPC asserts that every RPC declared in
// the generated ServiceDescs of the public CaaS API has an entry in
// auth.RegisteredMethods(). Default-deny only works if the method
// matrix is exhaustive — a missing entry is a security regression.
func TestPolicyRegistry_CoversEveryRPC(t *testing.T) {
	registered := auth.RegisteredMethods()
	covered := make(map[string]struct{}, len(registered))
	for _, m := range registered {
		covered[m] = struct{}{}
	}

	descs := []*grpc.ServiceDesc{
		&servicespb.CryptoService_ServiceDesc,
		&servicespb.CryptoPolicyService_ServiceDesc,
		&servicespb.AlgorithmDiscoveryService_ServiceDesc,
		&servicespb.ProviderService_ServiceDesc,
		&servicespb.KeyEstablishmentService_ServiceDesc,
		&servicespb.KeyManagementService_ServiceDesc,
		&servicespb.StreamingCryptoService_ServiceDesc,
	}

	for _, sd := range descs {
		for _, m := range sd.Methods {
			fqn := "/" + sd.ServiceName + "/" + m.MethodName
			_, ok := covered[fqn]
			require.True(t, ok, "policy registry missing method %s", fqn)
		}
		for _, s := range sd.Streams {
			fqn := "/" + sd.ServiceName + "/" + s.StreamName
			_, ok := covered[fqn]
			require.True(t, ok, "policy registry missing stream %s", fqn)
		}
	}
}

// TestPolicyRegistry_NoUnknownMethods catches stale entries: every
// registered FQN must correspond to a real generated method, otherwise
// the constant has drifted from the proto definition.
func TestPolicyRegistry_NoUnknownMethods(t *testing.T) {
	known := map[string]struct{}{}
	descs := []*grpc.ServiceDesc{
		&servicespb.CryptoService_ServiceDesc,
		&servicespb.CryptoPolicyService_ServiceDesc,
		&servicespb.AlgorithmDiscoveryService_ServiceDesc,
		&servicespb.ProviderService_ServiceDesc,
		&servicespb.KeyEstablishmentService_ServiceDesc,
		&servicespb.KeyManagementService_ServiceDesc,
		&servicespb.StreamingCryptoService_ServiceDesc,
	}
	for _, sd := range descs {
		for _, m := range sd.Methods {
			known["/"+sd.ServiceName+"/"+m.MethodName] = struct{}{}
		}
		for _, s := range sd.Streams {
			known["/"+sd.ServiceName+"/"+s.StreamName] = struct{}{}
		}
	}
	for _, m := range auth.RegisteredMethods() {
		_, ok := known[m]
		require.True(t, ok, "policy registry has unknown method %s", m)
	}
}
