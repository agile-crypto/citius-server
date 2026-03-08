// Package template contains the Template domain type and the Registry
// interface for algorithm template management.
//
// Domain type:
//   - Template is a plain Go struct (no proto embedding, no storage).
//     Templates are immutable value objects loaded from YAML at startup.
//     They define which algorithms are available, their security properties,
//     and scope-based selection criteria.
//
// Interface:
//   - Registry (domain service): Register, Get, List, and Select.
//     Select picks the best template for a given ScopeSpec, honouring
//     policy constraints and preferred properties.

package template
