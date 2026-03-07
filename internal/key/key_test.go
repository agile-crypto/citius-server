package key_test

import (
	"context"
	"testing"

	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/key"
)

func TestKey_VetForWrite_Create_happyPath(t *testing.T) {
	k := key.New(&storepb.StoredKey{
		PublicId:   "key_01HXYZ",
		Name:       "signing-key",
		TemplateId: "ecdsa-p256-sha256",
		Status:     storepb.KeyStatus_KEY_STATUS_ACTIVE,
	})
	if err := k.VetForWrite(context.Background(), core.OpCreate); err != nil {
		t.Errorf("VetForWrite(Create): unexpected error: %v", err)
	}
}

func TestKey_VetForWrite_Create_missingPublicId(t *testing.T) {
	k := key.New(&storepb.StoredKey{
		Name:       "signing-key",
		TemplateId: "ecdsa-p256-sha256",
	})
	err := k.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing PublicId")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument error, got %v", err)
	}
}

func TestKey_VetForWrite_Create_missingName(t *testing.T) {
	k := key.New(&storepb.StoredKey{
		PublicId:   "key_01HXYZ",
		TemplateId: "ecdsa-p256-sha256",
	})
	err := k.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing Name")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument error, got %v", err)
	}
}

func TestKey_VetForWrite_Create_missingTemplateId(t *testing.T) {
	k := key.New(&storepb.StoredKey{
		PublicId: "key_01HXYZ",
		Name:     "signing-key",
	})
	err := k.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing TemplateId")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument error, got %v", err)
	}
}

func TestKey_VetForWrite_Update_allowsMissingCreateTime(t *testing.T) {
	// Update only checks PublicId, Name
	k := key.New(&storepb.StoredKey{
		PublicId: "key_01HXYZ",
		Name:     "signing-key",
	})
	if err := k.VetForWrite(context.Background(), core.OpUpdate); err != nil {
		t.Errorf("VetForWrite(Update): unexpected error: %v", err)
	}
}

func TestKey_VetForWrite_Update_missingPublicId(t *testing.T) {
	k := key.New(&storepb.StoredKey{Name: "signing-key"})
	err := k.VetForWrite(context.Background(), core.OpUpdate)
	if err == nil {
		t.Fatal("expected error for missing PublicId on Update")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument error, got %v", err)
	}
}

func TestKey_Clone_independent(t *testing.T) {
	original := key.New(&storepb.StoredKey{
		PublicId: "key_01HXYZ",
		Name:     "signing-key",
		Labels:   map[string]string{"env": "prod"},
	})
	cloned := original.Clone()
	// Mutate the clone
	cloned.StoredKey().Labels["env"] = "dev"
	// Original should be unchanged
	if original.StoredKey().Labels["env"] != "prod" {
		t.Error("Clone() did not produce an independent copy — mutations alias the original")
	}
}

func TestKey_PublicId_accessor(t *testing.T) {
	k := key.New(&storepb.StoredKey{PublicId: "key_01HXYZ"})
	if k.StoredKey().PublicId != "key_01HXYZ" {
		t.Errorf("PublicID(): got %q want %q", k.PublicID(), "key_01HXYZ")
	}
}

// Compile-time assertion.
var _ core.VetForWriter = (*key.Key)(nil)

//--- Behavioural Test ---//

func TestKey_CanRotate_active(t *testing.T) {
	k := key.New(&storepb.StoredKey{
		PublicId: "key_01HXYZ", Name: "test", TemplateId: "ecdsa-p256",
		Status: storepb.KeyStatus_KEY_STATUS_ACTIVE,
	})
	if err := k.CanRotate(); err != nil {
		t.Errorf("CanRotate on ACTIVE key: unexpected error: %v", err)
	}
}

func TestKey_CanRotate_suspended(t *testing.T) {
	k := key.New(&storepb.StoredKey{
		PublicId: "key_01HXYZ", Name: "test", TemplateId: "ecdsa-p256",
		Status: storepb.KeyStatus_KEY_STATUS_SUSPENDED,
	})
	if err := k.CanRotate(); err == nil {
		t.Error("CanRotate on SUSPENDED key should return error")
	}
}

func TestKey_CanPerformCrypto_active(t *testing.T) {
	k := key.New(&storepb.StoredKey{
		PublicId: "key_01HXYZ", Name: "test", TemplateId: "ecdsa-p256",
		Status: storepb.KeyStatus_KEY_STATUS_ACTIVE,
	})
	if err := k.CanPerformCrypto(); err != nil {
		t.Errorf("CanPerformCrypto on ACTIVE key: unexpected error: %v", err)
	}
}

func TestKey_CanPerformCrypto_destroyed(t *testing.T) {
	k := key.New(&storepb.StoredKey{
		PublicId: "key_01HXYZ", Name: "test", TemplateId: "ecdsa-p256",
		Status: storepb.KeyStatus_KEY_STATUS_DESTROYED,
	})
	if err := k.CanPerformCrypto(); err == nil {
		t.Error("CanPerformCrypto on DESTROYED key should return error")
	}
}

// ---- Lifecycle Test ---//
func TestKey_TransitionTo_validTransitions(t *testing.T) {
	tests := []struct {
		from storepb.KeyStatus
		to   storepb.KeyStatus
	}{
		{storepb.KeyStatus_KEY_STATUS_PRE_ACTIVE, storepb.KeyStatus_KEY_STATUS_ACTIVE},
		{storepb.KeyStatus_KEY_STATUS_ACTIVE, storepb.KeyStatus_KEY_STATUS_SUSPENDED},
		{storepb.KeyStatus_KEY_STATUS_ACTIVE, storepb.KeyStatus_KEY_STATUS_DEACTIVATED},
		{storepb.KeyStatus_KEY_STATUS_ACTIVE, storepb.KeyStatus_KEY_STATUS_COMPROMISED},
		{storepb.KeyStatus_KEY_STATUS_SUSPENDED, storepb.KeyStatus_KEY_STATUS_ACTIVE},
		{storepb.KeyStatus_KEY_STATUS_SUSPENDED, storepb.KeyStatus_KEY_STATUS_DEACTIVATED},
		{storepb.KeyStatus_KEY_STATUS_DEACTIVATED, storepb.KeyStatus_KEY_STATUS_DESTROYED},
		{storepb.KeyStatus_KEY_STATUS_COMPROMISED, storepb.KeyStatus_KEY_STATUS_DESTROYED},
		{storepb.KeyStatus_KEY_STATUS_COMPROMISED, storepb.KeyStatus_KEY_STATUS_DESTROYED_COMPROMISED},
	}
	for _, tt := range tests {
		t.Run(tt.from.String()+"→"+tt.to.String(), func(t *testing.T) {
			k := key.New(&storepb.StoredKey{
				PublicId: "key_01HXYZ", Name: "test", TemplateId: "t",
				Status: tt.from,
			})
			if err := k.TransitionTo(tt.to); err != nil {
				t.Errorf("valid transition %s→%s returned error: %v", tt.from, tt.to, err)
			}
			if k.StoredKey().GetStatus() != tt.to {
				t.Errorf("status not updated: got %v want %v", k.StoredKey().GetStatus(), tt.to)
			}
		})
	}
}

func TestKey_TransitionTo_invalidTransitions(t *testing.T) {
	tests := []struct {
		from storepb.KeyStatus
		to   storepb.KeyStatus
	}{
		{storepb.KeyStatus_KEY_STATUS_DESTROYED, storepb.KeyStatus_KEY_STATUS_ACTIVE},             // terminal → anything
		{storepb.KeyStatus_KEY_STATUS_DESTROYED_COMPROMISED, storepb.KeyStatus_KEY_STATUS_ACTIVE}, // terminal → anything
		{storepb.KeyStatus_KEY_STATUS_ACTIVE, storepb.KeyStatus_KEY_STATUS_PRE_ACTIVE},            // backwards
		{storepb.KeyStatus_KEY_STATUS_ACTIVE, storepb.KeyStatus_KEY_STATUS_DESTROYED},             // skip deactivated
		{storepb.KeyStatus_KEY_STATUS_PRE_ACTIVE, storepb.KeyStatus_KEY_STATUS_SUSPENDED},         // must activate first
	}
	for _, tt := range tests {
		t.Run(tt.from.String()+"→"+tt.to.String(), func(t *testing.T) {
			k := key.New(&storepb.StoredKey{
				PublicId: "key_01HXYZ", Name: "test", TemplateId: "t",
				Status: tt.from,
			})
			if err := k.TransitionTo(tt.to); err == nil {
				t.Errorf("invalid transition %s→%s should return error", tt.from, tt.to)
			}
			// Status should NOT have changed
			if k.StoredKey().GetStatus() != tt.from {
				t.Errorf("status should remain %v on invalid transition, got %v",
					tt.from, k.StoredKey().GetStatus())
			}
		})
	}
}

func TestKey_IsTerminal(t *testing.T) {
	destroyed := key.New(&storepb.StoredKey{Status: storepb.KeyStatus_KEY_STATUS_DESTROYED})
	if !destroyed.IsTerminal() {
		t.Error("DESTROYED key should be terminal")
	}
	destroyedCompromised := key.New(&storepb.StoredKey{Status: storepb.KeyStatus_KEY_STATUS_DESTROYED_COMPROMISED})
	if !destroyedCompromised.IsTerminal() {
		t.Error("DESTROYED_COMPROMISED key should be terminal")
	}
	active := key.New(&storepb.StoredKey{Status: storepb.KeyStatus_KEY_STATUS_ACTIVE})
	if active.IsTerminal() {
		t.Error("ACTIVE key should not be terminal")
	}
}
