package core_test

import (
	"testing"

	"github.ibm.com/citius/citius-server/internal/core"
)

// Types tests are compile-only test to verify that the types exist and have the expected fields.

func TestKeyCreationSpec_hasRequiredFields(t *testing.T) {
	spec := core.KeyCreationSpec{
		Name:       "signing-key",
		TemplateID: "ecdsa-p256-sha256",
		PolicyID:   "pol_01HXYZ",
	}
	if spec.Name == "" {
		t.Error("Name field missing")
	}
}

func TestOperation_stringConstants(t *testing.T) {
	// Operation constants are untyped strings matching ValidateOperation's string param.
	tests := []struct {
		name string
		op   string
		want string
	}{
		{"sign", core.OperationSign, "sign"},
		{"verify", core.OperationVerify, "verify"},
		{"create_key", core.OperationCreateKey, "create_key"},
	}
	for _, tt := range tests {
		if tt.op != tt.want {
			t.Errorf("%s: got %q want %q", tt.name, tt.op, tt.want)
		}
	}
}

func TestKeyMaterial_hasFields(t *testing.T) {
	km := core.KeyMaterial{
		PublicKeyBytes:  []byte("pub"),
		PrivateKeyBytes: []byte("priv"),
		Algorithm:       "ecdsa-p256",
	}
	if km.Algorithm == "" {
		t.Error("Algorithm field missing")
	}
	if km.PublicKeyBytes == nil {
		t.Error("PublicKeyBytes field missing")
	}
}
