package core_test

import (
	"testing"

	"github.ibm.com/citius/citius-server/internal/core"
)

func TestScopeSpec_IsZero(t *testing.T) {
	tests := []struct {
		name string
		spec core.ScopeSpec
		want bool
	}{
		{"zero value", core.ScopeSpec{}, true},
		{"primitive only", core.ScopeSpec{Primitive: core.PrimitiveSignature}, false},
		{"scope only", core.ScopeSpec{Scope: core.SignatureScopeStandard}, false},
		{"both set", core.ScopeSpec{
			Primitive: core.PrimitiveSignature,
			Scope:     core.SignatureScopeStandard,
		}, false},
	}
	for _, tt := range tests {
		if got := tt.spec.IsZero(); got != tt.want {
			t.Errorf("ScopeSpec.IsZero(%s): got %v want %v", tt.name, got, tt.want)
		}
	}
}

func TestPrimitive_constants(t *testing.T) {
	// Verify all 10 primitive constants exist and have expected string values.
	tests := []struct {
		p    core.Primitive
		want string
	}{
		{core.PrimitiveSignature, "signature"},
		{core.PrimitiveAead, "aead"},
		{core.PrimitiveMac, "mac"},
		{core.PrimitiveKem, "kem"},
		{core.PrimitiveKeyAgreement, "key_agreement"},
		{core.PrimitiveKdf, "kdf"},
		{core.PrimitiveHash, "hash"},
		{core.PrimitiveKeyWrapping, "key_wrapping"},
		{core.PrimitiveSymmetricCipher, "symmetric_cipher"},
		{core.PrimitiveGenericSecret, "generic_secret"},
	}
	for _, tt := range tests {
		if string(tt.p) != tt.want {
			t.Errorf("Primitive: got %q want %q", tt.p, tt.want)
		}
	}
}

func TestScope_signatureConstants(t *testing.T) {
	tests := []struct {
		s    core.Scope
		want string
	}{
		{core.SignatureScopeStandard, "standard"},
		{core.SignatureScopeWithContext, "with_context"},
		{core.SignatureScopePrehashed, "prehashed"},
		{core.SignatureScopePrehashedWithContext, "prehashed_with_context"},
	}
	for _, tt := range tests {
		if string(tt.s) != tt.want {
			t.Errorf("Scope: got %q want %q", tt.s, tt.want)
		}
	}
}
