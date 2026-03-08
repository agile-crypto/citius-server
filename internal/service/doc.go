// Package service defines and implements application-layer use-case orchestrators.
//
// Application services coordinate multiple domain aggregates (key, policy, template,
// provider) to fulfil user-facing workflows like CreateKey, Sign, and Encrypt.
// They are distinct from domain services (policy.Engine, template.Registry,
// provider.Registry) which contain pure domain logic scoped to a single aggregate.
//
// Interfaces defined here:
//   - KeyOrchestrator:    key lifecycle workflows (create, rotate, destroy, ...)
//   - CryptoOrchestrator: cryptographic operation workflows (sign, verify, encrypt, ...)

package service
