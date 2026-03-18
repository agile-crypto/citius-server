package template_test

import (
	"testing"

	api "github.ibm.com/citius/citius-server/gen/go/types"
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
// MatchesProperties Tests
// ============================================================================

func TestMatchesProperties_tabledriven(t *testing.T) {
	ecdsaTmpl := template.NewTemplate(&api.TemplateInfo{
		TemplateId: "ecdsa-p256-sha256",
		Algorithm: &api.AlgorithmDetails{
			Algorithm: &api.AlgorithmDetails_Ecdsa{
				Ecdsa: &api.EcdsaParams{
					Curve: api.EllipticCurve_ELLIPTIC_CURVE_P256,
					Hash:  api.HashAlgorithm_HASH_ALGORITHM_SHA256,
				},
			},
		},
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
					},
				},
			},
		}},
		Status: api.TemplateStatus_TEMPLATE_STATUS_ACTIVE,
		AlgorithmProperties: map[string]string{
			"fips_approved": "true",
			"quantum_safe":  "false",
			"curve":         "P-256",
			"hash":          "SHA-256",
		},
	})

	mldsaTmpl := template.NewTemplate(&api.TemplateInfo{
		TemplateId: "ml-dsa-65",
		Algorithm: &api.AlgorithmDetails{
			Algorithm: &api.AlgorithmDetails_MlDsa{
				MlDsa: &api.MlDsaParams{
					ParameterSet: api.MlDsaParameterSet_ML_DSA_65,
				},
			},
		},
		ScopedCapabilities: []*api.ScopedCapabilities{{
			Scope: &api.ScopeSpecification{
				ScopeSpec: &api.ScopeSpecification_Signature{
					Signature: &api.SignatureScopeSpec{
						Scope: api.SignatureScope_SIGNATURE_SCOPE_STANDARD,
					},
				},
			},
		}},
		Status: api.TemplateStatus_TEMPLATE_STATUS_ACTIVE,
		AlgorithmProperties: map[string]string{
			"quantum_safe":  "true",
			"fips_approved": "false",
		},
	})

	tests := []struct {
		name       string
		tmpl       *template.Template
		properties map[string]string
		want       bool
	}{
		{
			name:       "fips_approved=true matches ecdsa",
			tmpl:       ecdsaTmpl,
			properties: map[string]string{"fips_approved": "true"},
			want:       true,
		},
		{
			name:       "fips_approved=true does not match mldsa",
			tmpl:       mldsaTmpl,
			properties: map[string]string{"fips_approved": "true"},
			want:       false,
		},
		{
			name:       "quantum_safe=true matches mldsa",
			tmpl:       mldsaTmpl,
			properties: map[string]string{"quantum_safe": "true"},
			want:       true,
		},
		{
			name:       "quantum_safe=true does not match ecdsa",
			tmpl:       ecdsaTmpl,
			properties: map[string]string{"quantum_safe": "true"},
			want:       false,
		},
		{
			name:       "algorithm property match: curve=P-256",
			tmpl:       ecdsaTmpl,
			properties: map[string]string{"curve": "P-256"},
			want:       true,
		},
		{
			name:       "algorithm property no match: curve=P-384",
			tmpl:       ecdsaTmpl,
			properties: map[string]string{"curve": "P-384"},
			want:       false,
		},
		{
			name:       "multiple properties - all must match",
			tmpl:       ecdsaTmpl,
			properties: map[string]string{"fips_approved": "true", "curve": "P-256"},
			want:       true,
		},
		{
			name:       "multiple properties - one fails",
			tmpl:       ecdsaTmpl,
			properties: map[string]string{"fips_approved": "true", "quantum_safe": "true"},
			want:       false,
		},
		{
			name:       "empty properties - always matches",
			tmpl:       ecdsaTmpl,
			properties: map[string]string{},
			want:       true,
		},
		{
			name:       "nil properties - always matches",
			tmpl:       ecdsaTmpl,
			properties: nil,
			want:       true,
		},
		{
			name:       "unknown property key - no match",
			tmpl:       ecdsaTmpl,
			properties: map[string]string{"nonexistent_key": "value"},
			want:       false,
		},
		{
			name: "nil AlgorithmProperties - no match for any property",
			tmpl: template.NewTemplate(&api.TemplateInfo{
				TemplateId: "bare-template",
			}),
			properties: map[string]string{"fips_approved": "true"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := template.MatchesProperties(tt.tmpl, tt.properties)
			if got != tt.want {
				t.Errorf("MatchesProperties(%v) = %v, want %v", tt.properties, got, tt.want)
			}
		})
	}
}
