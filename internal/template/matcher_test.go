package template_test

import (
	"testing"

	api "github.ibm.com/citius/citius-server/gen/go/api/types"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/template"
)

// ============================================================================
// MatchesScope Tests
// ============================================================================

func TestMatchesScope_tabledriven(t *testing.T) {
	tests := []struct {
		name  string
		tmpl  *template.Template
		scope core.ScopeSpec
		want  bool
	}{
		{
			name: "exact scope match - signature standard",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{{
					Scope: &api.ScopeSpecification{
						ScopeSpec: &api.ScopeSpecification_Signature{
							Signature: &api.SignatureScopeSpec{
								Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
							},
						},
					},
				}},
			}),
			scope: core.ScopeSpec{
				Primitive: core.PrimitiveSignature,
				Scope:     core.SignatureScopeStandard,
			},
			want: true,
		},
		{
			name: "no match - wrong scope variant",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{{
					Scope: &api.ScopeSpecification{
						ScopeSpec: &api.ScopeSpecification_Signature{
							Signature: &api.SignatureScopeSpec{
								Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
							},
						},
					},
				}},
			}),
			scope: core.ScopeSpec{
				Primitive: core.PrimitiveSignature,
				Scope:     core.SignatureScopePrehashed,
			},
			want: false,
		},
		{
			name: "no match - wrong primitive",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{{
					Scope: &api.ScopeSpecification{
						ScopeSpec: &api.ScopeSpecification_Signature{
							Signature: &api.SignatureScopeSpec{
								Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
							},
						},
					},
				}},
			}),
			scope: core.ScopeSpec{
				Primitive: core.PrimitiveAead,
				Scope:     core.AeadScopeStandard,
			},
			want: false,
		},
		{
			name: "zero scope - matches all (no scope filter)",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{{
					Scope: &api.ScopeSpecification{
						ScopeSpec: &api.ScopeSpecification_Signature{
							Signature: &api.SignatureScopeSpec{
								Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
							},
						},
					},
				}},
			}),
			scope: core.ScopeSpec{},
			want:  true,
		},
		{
			name: "primitive only - any scope variant matches",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{{
					Scope: &api.ScopeSpecification{
						ScopeSpec: &api.ScopeSpecification_Signature{
							Signature: &api.SignatureScopeSpec{
								Scope: api.SignatureScope_SIGNATURE_SCOPE_PREHASHED,
							},
						},
					},
				}},
			}),
			scope: core.ScopeSpec{
				Primitive: core.PrimitiveSignature,
			},
			want: true,
		},
		{
			name: "template has multiple scopes - one matches",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{
					{
						Scope: &api.ScopeSpecification{
							ScopeSpec: &api.ScopeSpecification_Signature{
								Signature: &api.SignatureScopeSpec{
									Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
								},
							},
						},
					},
					{
						Scope: &api.ScopeSpecification{
							ScopeSpec: &api.ScopeSpecification_Signature{
								Signature: &api.SignatureScopeSpec{
									Scope: api.SignatureScope_SIGNATURE_SCOPE_PREHASHED,
								},
							},
						},
					},
				},
			}),
			scope: core.ScopeSpec{
				Primitive: core.PrimitiveSignature,
				Scope:     core.SignatureScopePrehashed,
			},
			want: true,
		},
		{
			name: "template has no scopes - never matches",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				ScopedCapabilities: []*api.ScopedCapabilities{},
			}),
			scope: core.ScopeSpec{
				Primitive: core.PrimitiveSignature,
				Scope:     core.SignatureScopeStandard,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := template.MatchesScope(tt.tmpl, tt.scope)
			if got != tt.want {
				t.Errorf("MatchesScope(%v) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

// ============================================================================
// MatchesScope — Security Filter Tests
// ============================================================================

func boolPtr(v bool) *bool { return &v }

func TestMatchesScope_securityFilters_tabledriven(t *testing.T) {
	// ECDSA template: fips_approved=true, quantum_safe=false
	ecdsaTmpl := template.NewTemplate(&api.TemplateInfo{
		TemplateId: "ecdsa-p256-sha256",
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
						Security: &api.UniversalSecurityProperties{
							FipsApproved: boolPtr(true),
							QuantumSafe:  boolPtr(false),
						},
					},
				},
			},
		}},
	})

	// ML-DSA template: quantum_safe=true, fips_approved=false
	mldsaTmpl := template.NewTemplate(&api.TemplateInfo{
		TemplateId: "ml-dsa-65",
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
						Security: &api.UniversalSecurityProperties{
							QuantumSafe:  boolPtr(true),
							FipsApproved: boolPtr(false),
						},
					},
				},
			},
		}},
	})

	// Bare template: no security properties in scope
	bareTmpl := template.NewTemplate(&api.TemplateInfo{
		TemplateId: "bare-sig",
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
					},
				},
			},
		}},
	})

	tests := []struct {
		name  string
		tmpl  *template.Template
		scope core.ScopeSpec
		want  bool
	}{
		{
			name: "fips_approved=true matches ecdsa",
			tmpl: ecdsaTmpl,
			scope: core.ScopeSpec{
				Primitive:    core.PrimitiveSignature,
				FIPSApproved: boolPtr(true),
			},
			want: true,
		},
		{
			name: "fips_approved=true does not match mldsa",
			tmpl: mldsaTmpl,
			scope: core.ScopeSpec{
				Primitive:    core.PrimitiveSignature,
				FIPSApproved: boolPtr(true),
			},
			want: false,
		},
		{
			name: "quantum_safe=true matches mldsa",
			tmpl: mldsaTmpl,
			scope: core.ScopeSpec{
				Primitive:   core.PrimitiveSignature,
				QuantumSafe: boolPtr(true),
			},
			want: true,
		},
		{
			name: "quantum_safe=true does not match ecdsa",
			tmpl: ecdsaTmpl,
			scope: core.ScopeSpec{
				Primitive:   core.PrimitiveSignature,
				QuantumSafe: boolPtr(true),
			},
			want: false,
		},
		{
			name: "both fips and quantum_safe required - no template satisfies both",
			tmpl: ecdsaTmpl,
			scope: core.ScopeSpec{
				Primitive:    core.PrimitiveSignature,
				FIPSApproved: boolPtr(true),
				QuantumSafe:  boolPtr(true),
			},
			want: false,
		},
		{
			name: "no security filter - primitive only - matches any",
			tmpl: ecdsaTmpl,
			scope: core.ScopeSpec{
				Primitive: core.PrimitiveSignature,
			},
			want: true,
		},
		{
			name: "bare template (nil security) fails fips filter",
			tmpl: bareTmpl,
			scope: core.ScopeSpec{
				Primitive:    core.PrimitiveSignature,
				FIPSApproved: boolPtr(true),
			},
			want: false,
		},
		{
			name: "bare template (nil security) passes without security filter",
			tmpl: bareTmpl,
			scope: core.ScopeSpec{
				Primitive: core.PrimitiveSignature,
			},
			want: true,
		},
		{
			name: "fips_approved=false explicitly matches mldsa",
			tmpl: mldsaTmpl,
			scope: core.ScopeSpec{
				Primitive:    core.PrimitiveSignature,
				FIPSApproved: boolPtr(false),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := template.MatchesScope(tt.tmpl, tt.scope)
			if got != tt.want {
				t.Errorf("MatchesScope(%v) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}
