package template

import (
	"github.ibm.com/citius/citius-server/internal/core"
)

// MatchesScope reports whether tmpl serves the given scope.
// If want is a zero-value ScopeSpec (both Primitive and Scope empty),
// all templates match (no scope filter applied).
// Inspects the template's ScopedCapabilities and checks if any ScopeSpecification
// matches the requested core.ScopeSpec (Primitive + optional Scope variant).
func MatchesScope(tmpl *Template, want core.ScopeSpec) bool {
	if want.IsZero() {
		return true
	}
	for _, sc := range tmpl.GetScopedCapabilities() {
		got := scopeSpecFromProto(sc.GetScope())
		if got.Primitive == want.Primitive {
			// If caller specified a scope variant, match it too.
			// If caller only specified primitive (Scope == ""), any variant matches.
			if want.Scope == "" || got.Scope == want.Scope {
				return true
			}
		}
	}
	return false
}

// MatchesProperties reports whether tmpl satisfies ALL required properties.
// An empty or nil properties map matches every template.
// Properties are looked up in tmpl.Proto().GetAlgorithmProperties(), which
// returns a flat map of all algorithm-derived parameters (fips_approved,
// quantum_safe, curve, hash, key_size_bits, etc.).
func MatchesProperties(tmpl *Template, properties map[string]string) bool {
	for key, val := range properties {
		if !templateHasProperty(tmpl, key, val) {
			return false
		}
	}
	return true
}

// templateHasProperty checks a single property key/value against a template.
// Looks up the property in the template's AlgorithmProperties map.
func templateHasProperty(t *Template, key, value string) bool {
	props := t.Proto().GetAlgorithmProperties()
	if props == nil {
		return false
	}
	v, ok := props[key]
	return ok && v == value
}
