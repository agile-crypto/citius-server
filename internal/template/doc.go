// Package template contains the Template domain type and the Registry
// interface for algorithm template management.
//
// Domain type:
//   - Template wraps *api.TemplateInfo as a pragmatic trade-off, NOT the
//     same domain driven design pattern as key.Key / policy.Policy / provider.Instance.
//     Those types wrap storage protos (caas.storage.v1) at the Repository
//     boundary. Template wraps an API-surface proto (caas.crypto.v1)
//     because TemplateInfo has multiple deeply nested algorithm/scope types
//     that would be costly to replicate as Go structs for zero behavioral
//     benefit. Templates are immutable reference data loaded from
//     proto-JSON at startup, never persisted to durable storage.
//   - Proto() exposes the embedded TemplateInfo
//     (there is no storage proto for templates).
//   - Proto types do NOT escape beyond this package boundary: all other
//     packages interact with Template through domain-typed accessors
//     and core.ScopeSpec.
//
// Interface:
//   - Registry (domain service): Register, Get, List, and Select.
//     Select picks the best template for a given ScopeSpec, honouring
//     policy constraints and preferred properties.
//
// Proto -> Domain conversion:
//   - scopeSpecFromProto (unexported) converts *api.ScopeSpecification →
//     core.ScopeSpec for internal use by Select. This is NOT an
//     Anti-Corruption Layer — it is a localised conversion that
//     interprets the template's own proto capabilities in domain terms.

package template
