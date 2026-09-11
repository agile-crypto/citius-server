package server

import (
	"context"

	engerr "github.com/agile-crypto/citius-core/errors"
	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/template"
	cryptogrpc "github.com/agile-crypto/citius-server/internal/grpc/crypto"
	discogrpc "github.com/agile-crypto/citius-server/internal/grpc/discovery"
	keyestgrpc "github.com/agile-crypto/citius-server/internal/grpc/keyestablishment"
	keygrpc "github.com/agile-crypto/citius-server/internal/grpc/keymanagement"
	policygrpc "github.com/agile-crypto/citius-server/internal/grpc/policy"
	providergrpc "github.com/agile-crypto/citius-server/internal/grpc/provider"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
	streamgrpc "github.com/agile-crypto/citius-server/internal/grpc/streaming"
	"github.com/agile-crypto/citius-server/internal/service"

	"google.golang.org/grpc"
)

// ============================================================================
// Composition root
// ============================================================================
//
// This is the one place allowed to know about every service, every domain and
// every adapter — that is what a composition root is for. Everything below it
// knows only its own capability.
//
// Three decisions live here and nowhere else:
//
//   - which services this deployment exposes,
//   - which implementation backs each capability (Vault storage today, SQL or a
//     remote adapter later — the placement switch of the deployment plan),
//   - the startup validation that rejects incoherent combinations.
//
// A deployment that serves a subset gets its own composition root rather than a
// configuration flag here: a policy-only server is a main package that imports
// policygrpc and internal/policy, and nothing else. That is the only way the
// import graph actually shrinks, since Go links what a binary imports, not what
// it calls.

const (
	validateOp engerr.Op = "server.(Services).Validate"
	registerOp engerr.Op = "server.RegisterAll"
)

// FactorySet is the full-server bundle of capability factories.
//
// It is a convenience for a deployment that serves everything, not a required
// abstraction: a single-service deployment should pass its one factory
// directly. It lives in the composition root because it names every domain, and
// anything that names every domain must sit where importing every domain is
// already true.
//
// A nil field means the capability was not configured; Validate reports the
// combinations that cannot work.
type FactorySet struct {
	Keys      service.KeyOrchestratorFactory
	Crypto    service.CryptoOrchestratorFactory
	Policy    policy.EngineFactory
	Instances provider.InstanceManagerFactory
	Templates template.RegistryFactory
	Catalog   provider.RegistryFactory

	// AuthorizeKey and AuthorizePolicy are the per-resource authorization
	// checks handed to the handlers that perform them. They are required
	// whenever such a service is enabled: a deployment that runs without
	// authorization sets them to AllowAllKeyNames() / AllowAllPolicyNames()
	// rather than leaving them nil, so that "no authorization" is a visible
	// choice here instead of an accident.
	AuthorizeKey    grpcstatus.AuthorizeKeyName
	AuthorizePolicy grpcstatus.AuthorizePolicyName
}

// AllowAllKeyNames returns a key check that authorizes everything, for a
// deployment that intentionally runs without per-resource authorization.
func AllowAllKeyNames() grpcstatus.AuthorizeKeyName {
	return func(context.Context, engerr.Op, string) error { return nil }
}

// AllowAllPolicyNames returns a policy check that authorizes everything, for a
// deployment that intentionally runs without per-resource authorization.
func AllowAllPolicyNames() grpcstatus.AuthorizePolicyName {
	return func(context.Context, engerr.Op, string) error { return nil }
}

// Services selects which gRPC services a deployment exposes. The zero value
// exposes nothing, which Validate rejects.
type Services struct {
	KeyManagement    bool
	Crypto           bool
	CryptoPolicy     bool
	Discovery        bool
	Provider         bool
	KeyEstablishment bool
	Streaming        bool
}

// Validate checks the deployment before it accepts connections. It reports:
//
//   - no service enabled;
//   - a service enabled whose factories or authorization checks are missing,
//     rather than failing on the first RPC.
//
// TODO: two checks from the deployment plan are not expressible yet, because
// this package does not model where a domain runs. Once a placement config
// exists, Validate must also reject Streaming enabled while any domain it
// touches is remote (mixed local/remote multi-part sessions are out of scope
// and must fail at startup, not mid-stream), and a mixed local/remote pair that
// shares one storage.Storage.
func (s Services) Validate(f FactorySet) error {
	ctx := context.Background()

	if !s.anyEnabled() {
		return engerr.New(ctx, validateOp, engerr.CodeInvalidArgument,
			"no service enabled: the server would accept connections it cannot serve")
	}

	// requirement pairs a human-readable dependency with whether it is present,
	// so the loop below reports the first missing one by name.
	type requirement struct {
		service string
		needs   string
		present bool
	}
	var reqs []requirement
	if s.KeyManagement {
		reqs = append(reqs,
			requirement{"KeyManagement", "key orchestrator factory", f.Keys != nil},
			requirement{"KeyManagement", "key authorization check", f.AuthorizeKey != nil},
			requirement{"KeyManagement", "policy authorization check", f.AuthorizePolicy != nil},
		)
	}
	if s.Crypto {
		reqs = append(reqs,
			requirement{"Crypto", "crypto orchestrator factory", f.Crypto != nil},
			requirement{"Crypto", "key authorization check", f.AuthorizeKey != nil},
		)
	}
	if s.CryptoPolicy {
		reqs = append(reqs,
			requirement{"CryptoPolicy", "policy engine factory", f.Policy != nil},
			requirement{"CryptoPolicy", "policy authorization check", f.AuthorizePolicy != nil},
		)
	}
	if s.Discovery {
		reqs = append(reqs, requirement{"Discovery", "template registry factory", f.Templates != nil})
	}
	if s.Provider {
		reqs = append(reqs,
			requirement{"Provider", "provider registry factory", f.Catalog != nil},
			requirement{"Provider", "provider instance manager factory", f.Instances != nil},
		)
	}
	if s.KeyEstablishment {
		reqs = append(reqs,
			requirement{"KeyEstablishment", "crypto orchestrator factory", f.Crypto != nil},
			requirement{"KeyEstablishment", "key orchestrator factory", f.Keys != nil},
		)
	}
	if s.Streaming {
		reqs = append(reqs, requirement{"Streaming", "crypto orchestrator factory", f.Crypto != nil})
	}

	for _, r := range reqs {
		if !r.present {
			return engerr.New(ctx, validateOp, engerr.CodeInvalidArgument,
				r.service+" is enabled but its "+r.needs+" is missing")
		}
	}
	return nil
}

// anyEnabled reports whether the deployment exposes at least one service.
func (s Services) anyEnabled() bool {
	return s.KeyManagement || s.Crypto || s.CryptoPolicy || s.Discovery ||
		s.Provider || s.KeyEstablishment || s.Streaming
}

// RegisterAll registers exactly the services selected in s, building each
// handler from the factories it needs — one call per service package.
//
// It calls Validate first, so a misconfigured deployment fails here rather than
// on its first RPC. ctx is used only to build errors during construction; it is
// not retained by any handler.
//
// Exhaustive iteration yields a high cognitive and cyclomatic complexity score, so this function is exempted from that linter check.
//
//nolint:gocognit,cyclop
func RegisterAll(ctx context.Context, reg grpc.ServiceRegistrar, s Services, f FactorySet) error {
	if err := s.Validate(f); err != nil {
		return engerr.Wrap(ctx, registerOp, err)
	}

	if s.KeyManagement {
		h, err := keygrpc.New(ctx, f.Keys, f.AuthorizeKey, f.AuthorizePolicy)
		if err != nil {
			return engerr.Wrap(ctx, registerOp, err)
		}
		keygrpc.Register(reg, h)
	}
	if s.Crypto {
		h, err := cryptogrpc.New(ctx, f.Crypto, f.AuthorizeKey)
		if err != nil {
			return engerr.Wrap(ctx, registerOp, err)
		}
		cryptogrpc.Register(reg, h)
	}
	if s.CryptoPolicy {
		h, err := policygrpc.New(ctx, f.Policy, f.AuthorizePolicy)
		if err != nil {
			return engerr.Wrap(ctx, registerOp, err)
		}
		policygrpc.Register(reg, h)
	}
	if s.Discovery {
		h, err := discogrpc.New(ctx, f.Templates)
		if err != nil {
			return engerr.Wrap(ctx, registerOp, err)
		}
		discogrpc.Register(reg, h)
	}
	if s.Provider {
		h, err := providergrpc.New(ctx, f.Catalog, f.Instances)
		if err != nil {
			return engerr.Wrap(ctx, registerOp, err)
		}
		providergrpc.Register(reg, h)
	}
	if s.KeyEstablishment {
		h, err := keyestgrpc.New(ctx, f.Crypto, f.Keys)
		if err != nil {
			return engerr.Wrap(ctx, registerOp, err)
		}
		keyestgrpc.Register(reg, h)
	}
	if s.Streaming {
		h, err := streamgrpc.New(ctx, f.Crypto)
		if err != nil {
			return engerr.Wrap(ctx, registerOp, err)
		}
		streamgrpc.Register(reg, h)
	}
	return nil
}
