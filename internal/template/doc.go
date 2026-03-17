// Package template contains the Template domain type and the Registry
// interface for algorithm template management.
//
// Domain type:
//   - Template wraps *api.TemplateInfo (proto), following the same
//     domain-wrapping pattern used by key.Key, policy.Policy, and
//     provider.Instance.  Templates are loaded from JSON at startup
//     and stored in Vault InmemStorage for consistent access via
//     the Registry interface.
//
// Interface:
//   - Registry (domain service): Register, Get, List, and Select.
//     Select picks the best template for a given ScopeSpec, honouring
//     policy constraints and preferred properties.

package template
