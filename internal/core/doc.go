// Package core is the core abstraction layer for the cryptographic service.
//
// This package defines cross-domain interfaces (Storage, KeyOrchestrator,
// CryptoOrchestrator, PolicyEngine, TemplateRegistry, ProviderRegistry,
// ProviderInstance, ProviderInstanceManager), factory types, shared value types,
// and the Service facade that wires all subsystems together.
//
// Import policy:
//   - internal/core/ MUST NOT import any concrete implementation package
//     (internal/key/, internal/policy/, etc.) except via interfaces.
//   - internal/core/ MUST NOT import generated code from gen/ at the interface boundary.
//   - internal/core/ MUST NOT import google.golang.org/grpc except in
//     internal/errors/codes.go for the GRPCCode() mapper.
//   - All domain-specific packages communicate through interfaces defined here.
package core
