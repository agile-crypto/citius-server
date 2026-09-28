package providergrpc

import (
	"context"
	"slices"
	"strings"

	typespb "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/provider"
	"google.golang.org/protobuf/proto"
)

// The read-only half of ProviderService reports the provider instances the
// registry serves: each registered Backend is an instance, named by Name()
// and of the provider Type() reports. Instance CRUD is separate and not yet
// implemented, so every instance listed here is enabled and has no stored
// configuration.

// registered returns the registry's backends ordered by instance name.
func registered(ctx context.Context, reg provider.Registry) []provider.Backend {
	all := slices.DeleteFunc(slices.Clone(reg.List(ctx)), func(b provider.Backend) bool { return b == nil })
	slices.SortFunc(all, func(a, b provider.Backend) int { return strings.Compare(a.Name(), b.Name()) })
	return all
}

// implementationOf returns a copy of what b reports about its
// implementation, or nil if it reports nothing.
func implementationOf(b provider.Backend) *typespb.ImplementationProperties {
	props := provider.ImplementationOf(b)
	if props == nil {
		return nil
	}
	out, _ := proto.Clone(props).(*typespb.ImplementationProperties)
	return out
}

// instanceInfo describes backend b as a provider instance. The
// implementation it reports goes in implementation_override: it is the
// instance's own, which is what a caller filtering on FIPS 140 needs, and it
// may differ between instances of one provider (openssl and openssl-fips).
func instanceInfo(b provider.Backend) *typespb.ProviderInstance {
	return &typespb.ProviderInstance{
		InstanceId:             b.Name(),
		ProviderId:             b.Type(),
		DisplayName:            b.Name(),
		ImplementationOverride: implementationOf(b),
	}
}
