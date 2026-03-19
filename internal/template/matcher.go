package template

import (
	"github.ibm.com/citius/citius-server/internal/core"
)

// MatchesScope reports whether tmpl serves the given scope.
// If want is a zero-value ScopeSpec (all fields zero/nil),
// all templates match (no scope filter applied).
// Inspects the template's ScopedCapabilities and checks if any ScopeSpecification
// matches the requested core.ScopeSpec (Primitive + optional Scope variant +
// optional security filters).
func MatchesScope(tmpl *Template, want core.ScopeSpec) bool {
	if want.IsZero() {
		return true
	}
	for _, sc := range tmpl.GetScopedCapabilities() {
		got := scopeSpecFromProto(sc.GetScope())
		if got.Primitive != want.Primitive {
			continue
		}
		// If caller specified a scope variant, match it too.
		// If caller only specified primitive (Scope == ""), any variant matches.
		if want.Scope != "" && got.Scope != want.Scope {
			continue
		}
		// If caller specified security filters, the template's scope
		// must satisfy them.
		if !matchesSecurity(want, got) {
			continue
		}
		return true
	}
	return false
}

// matchesSecurity checks whether template-side security properties (got)
// satisfy the caller-side security filter (want).
//
// Nil-semantics per field:
//   - want field nil  -> don't care -> always passes
//   - want field non-nil -> got field must be non-nil and equal
func matchesSecurity(want, got core.ScopeSpec) bool {
	if want.FIPSApproved != nil {
		if got.FIPSApproved == nil || *got.FIPSApproved != *want.FIPSApproved {
			return false
		}
	}
	if want.QuantumSafe != nil {
		if got.QuantumSafe == nil || *got.QuantumSafe != *want.QuantumSafe {
			return false
		}
	}
	return true
}
