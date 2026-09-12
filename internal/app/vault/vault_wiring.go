//go:build vault_plugin

package vault

import (
	"context"

	"github.com/agile-crypto/citius-core/policy"
	"github.com/agile-crypto/citius-core/provider"
	"github.com/agile-crypto/citius-core/service"
	"github.com/agile-crypto/citius-core/template"
	"github.com/agile-crypto/citius-server/internal/storage"
)

// ============================================================================
// Vault deployment wiring
// ============================================================================
//
// This file is the Vault-plugin half of the wiring, and the only place a
// storage.Storage is threaded through per request — a genuine property of the
// Vault deployment, where the plugin receives a logical.Storage on every
// inbound *logical.Request and must use exactly that one.
//
// The gRPC handler packages do not, and must not, import this. They accept the
// domain factory types (policy.EngineFactory, service.KeyOrchestratorFactory,
// …), which say nothing about storage; binding a request's storage into those
// factories happens here.
//
// This package belongs on the adapter tier of the module topology and should
// move to the vault-storage module when that split happens. Nothing above it
// should acquire an import of it in the meantime.

// Vault*Builder types build one subsystem over one request's storage. They are
// the storage-taking form; Bind converts them into the storage-free domain
// factories the transports accept.
type (
	VaultKeyBuilder      func(ctx context.Context, store storage.Storage) (service.KeyOrchestrator, error)
	VaultCryptoBuilder   func(ctx context.Context, store storage.Storage) (service.CryptoOrchestrator, error)
	VaultPolicyBuilder   func(ctx context.Context, store storage.Storage) (policy.Engine, error)
	VaultInstanceBuilder func(ctx context.Context, store storage.Storage) (provider.InstanceManager, error)
	VaultTemplateBuilder func(ctx context.Context, store storage.Storage) (template.Registry, error)
	VaultCatalogBuilder  func(ctx context.Context, store storage.Storage) (provider.Registry, error)
)

// Every capability is a builder, including the two that are startup-built and
// immutable in today's deployments: the template catalogue is Vault-stored, so
// its storage is a property of the mount rather than of the process, and the
// provider registry holds compiled-in backends that need no storage at all.
//
// Modelling them uniformly is deliberate. Whether a capability is static is a
// decision for the implementation, not for the port: a builder that ignores its
// store argument and closes over one registry expresses "static" exactly, while
// the reverse — a plain field — cannot express "per mount" or the SQL-backed
// catalogue we expect later. app.FixedTemplates and app.FixedProviders are the
// static choice, made where it belongs.

// VaultProviders holds the storage-taking builders chosen at plugin setup —
// which repository, registry and engine implementations this backend uses.
//
// Unset builders mean the corresponding paths are not registered. It is created
// once at setup and is safe for concurrent use; the per-request binding happens
// in Bind.
type VaultProviders struct {
	KeyFn      VaultKeyBuilder
	CryptoFn   VaultCryptoBuilder
	PolicyFn   VaultPolicyBuilder
	InstanceFn VaultInstanceBuilder
	TemplateFn VaultTemplateBuilder
	CatalogFn  VaultCatalogBuilder
}

// BoundFactories is one request's worth of domain factories: the same types the
// gRPC handler packages accept, with this request's storage already captured.
//
// A field is nil when the corresponding capability was not configured, so a
// backend registering only the policy paths never constructs a key repository.
type BoundFactories struct {
	Keys      service.KeyOrchestratorFactory
	Crypto    service.CryptoOrchestratorFactory
	Policy    policy.EngineFactory
	Instances provider.InstanceManagerFactory
	Templates template.RegistryFactory
	Catalog   provider.RegistryFactory
}

// Bind pins one request's storage into the configured builders.
//
// Call it at the top of each registered path callback, passing req.Storage;
// passing a different store would silently read and write the wrong Vault
// mount. The returned factories are lazy — a path that only reads policy never
// invokes the key builder — and single-request scoped.
func (p *VaultProviders) Bind(store storage.Storage) BoundFactories { panic("not implemented") }
