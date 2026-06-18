package key_test

import (
	"context"
	"testing"

	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	types "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"github.ibm.com/citius/citius-server/internal/key"
)

func TestKey_VetForWrite_Create_happyPath(t *testing.T) {
	k := key.NewKey(&storepb.Key{
		PublicId:           "key_01HXYZ",
		Name:               "signing-key",
		Primitive:          "signature",
		Status:             types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE,
		ScopeSpecification: []byte(`{"primitive":"signature"}`),
	})
	if err := k.VetForWrite(context.Background(), core.OpCreate); err != nil {
		t.Errorf("VetForWrite(Create): unexpected error: %v", err)
	}
}

func TestKey_VetForWrite_Create_missingPublicId(t *testing.T) {
	k := key.NewKey(&storepb.Key{
		Name:      "signing-key",
		Primitive: "signature",
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
	k := key.NewKey(&storepb.Key{
		PublicId:  "key_01HXYZ",
		Primitive: "signature",
	})
	err := k.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing Name")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument error, got %v", err)
	}
}

func TestKey_VetForWrite_Create_missingPrimitive(t *testing.T) {
	k := key.NewKey(&storepb.Key{
		PublicId: "key_01HXYZ",
		Name:     "signing-key",
	})
	err := k.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing Primitive")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument error, got %v", err)
	}
}

func TestKey_VetForWrite_Update_allowsMissingCreateTime(t *testing.T) {
	// Update only checks PublicId, Name
	k := key.NewKey(&storepb.Key{
		PublicId: "key_01HXYZ",
		Name:     "signing-key",
	})
	if err := k.VetForWrite(context.Background(), core.OpUpdate); err != nil {
		t.Errorf("VetForWrite(Update): unexpected error: %v", err)
	}
}

func TestKey_VetForWrite_Update_missingPublicId(t *testing.T) {
	k := key.NewKey(&storepb.Key{Name: "signing-key"})
	err := k.VetForWrite(context.Background(), core.OpUpdate)
	if err == nil {
		t.Fatal("expected error for missing PublicId on Update")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument error, got %v", err)
	}
}

func TestKey_Clone_independent(t *testing.T) {
	original := key.NewKey(&storepb.Key{
		PublicId: "key_01HXYZ",
		Name:     "signing-key",
		Labels:   map[string]string{"env": "prod"},
	})
	cloned := original.Clone()
	// Mutate the clone
	cloned.Labels["env"] = "dev"
	// Original should be unchanged
	if original.Labels["env"] != "prod" {
		t.Error("Clone() did not produce an independent copy — mutations alias the original")
	}
}

func TestKey_PublicId_accessor(t *testing.T) {
	k := key.NewKey(&storepb.Key{PublicId: "key_01HXYZ"})
	if k.PublicId != "key_01HXYZ" {
		t.Errorf("PublicID(): got %q want %q", k.GetPublicId(), "key_01HXYZ")
	}
}

// Compile-time assertion.
var _ core.VetForWriter = (*key.Key)(nil)

//--- Behavioural Test ---//

func TestKey_CanRotate_active(t *testing.T) {
	k := key.NewKey(&storepb.Key{
		PublicId: "key_01HXYZ", Name: "test", Primitive: "ecdsa-p256",
		Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE,
	})
	if err := k.CanRotate(); err != nil {
		t.Errorf("CanRotate on ACTIVE key: unexpected error: %v", err)
	}
}

func TestKey_CanRotate_suspended(t *testing.T) {
	k := key.NewKey(&storepb.Key{
		PublicId: "key_01HXYZ", Name: "test", Primitive: "ecdsa-p256",
		Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED,
	})
	if err := k.CanRotate(); err == nil {
		t.Error("CanRotate on SUSPENDED key should return error")
	}
}

func TestKey_CanPerformCrypto_active(t *testing.T) {
	k := key.NewKey(&storepb.Key{
		PublicId: "key_01HXYZ", Name: "test", Primitive: "ecdsa-p256",
		Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE,
	})
	if err := k.CanPerformCrypto(); err != nil {
		t.Errorf("CanPerformCrypto on ACTIVE key: unexpected error: %v", err)
	}
}

func TestKey_CanPerformCrypto_destroyed(t *testing.T) {
	k := key.NewKey(&storepb.Key{
		PublicId: "key_01HXYZ", Name: "test", Primitive: "ecdsa-p256",
		Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED,
	})
	if err := k.CanPerformCrypto(); err == nil {
		t.Error("CanPerformCrypto on DESTROYED key should return error")
	}
}

// ---- Lifecycle Test ---//
func TestKey_TransitionTo_validTransitions(t *testing.T) {
	tests := []struct {
		from types.KeyLifecycleState
		to   types.KeyLifecycleState
	}{
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_PRE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED},
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED},
	}
	for _, tt := range tests {
		t.Run(tt.from.String()+"→"+tt.to.String(), func(t *testing.T) {
			k := key.NewKey(&storepb.Key{
				PublicId: "key_01HXYZ", Name: "test", Primitive: "t",
				Status: tt.from,
			})
			if err := k.TransitionTo(tt.to); err != nil {
				t.Errorf("valid transition %s→%s returned error: %v", tt.from, tt.to, err)
			}
			if k.GetStatus() != tt.to {
				t.Errorf("status not updated: got %v want %v", k.GetStatus(), tt.to)
			}
		})
	}
}

func TestKey_TransitionTo_invalidTransitions(t *testing.T) {
	tests := []struct {
		from types.KeyLifecycleState
		to   types.KeyLifecycleState
	}{
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE},             // terminal → anything
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE}, // terminal → anything
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_PRE_ACTIVE},            // backwards
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED},             // skip deactivated
		{types.KeyLifecycleState_KEY_LIFECYCLE_STATE_PRE_ACTIVE, types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED},         // must activate first
	}
	for _, tt := range tests {
		t.Run(tt.from.String()+"→"+tt.to.String(), func(t *testing.T) {
			k := key.NewKey(&storepb.Key{
				PublicId: "key_01HXYZ", Name: "test", Primitive: "t",
				Status: tt.from,
			})
			if err := k.TransitionTo(tt.to); err == nil {
				t.Errorf("invalid transition %s→%s should return error", tt.from, tt.to)
			}
			// Status should NOT have changed
			if k.GetStatus() != tt.from {
				t.Errorf("status should remain %v on invalid transition, got %v",
					tt.from, k.GetStatus())
			}
		})
	}
}

func TestKey_IsTerminal(t *testing.T) {
	destroyed := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED})
	if !destroyed.IsTerminal() {
		t.Error("DESTROYED key should be terminal")
	}
	destroyedCompromised := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED})
	if !destroyedCompromised.IsTerminal() {
		t.Error("DESTROYED_COMPROMISED key should be terminal")
	}
	active := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE})
	if active.IsTerminal() {
		t.Error("ACTIVE key should not be terminal")
	}
}

// CanPerformOriginatingCrypto

func TestKey_CanPerformOriginatingCrypto_active_succeeds(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE})
	if err := k.CanPerformOriginatingCrypto(); err != nil {
		t.Errorf("CanPerformOriginatingCrypto on ACTIVE key: unexpected error: %v", err)
	}
}

func TestKey_CanPerformOriginatingCrypto_suspended_fails(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED})
	if err := k.CanPerformOriginatingCrypto(); err == nil {
		t.Error("CanPerformOriginatingCrypto on SUSPENDED key: expected error, got nil")
	}
}

func TestKey_CanPerformOriginatingCrypto_deactivated_fails(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED})
	if err := k.CanPerformOriginatingCrypto(); err == nil {
		t.Error("CanPerformOriginatingCrypto on DEACTIVATED key: expected error, got nil")
	}
}

func TestKey_CanPerformOriginatingCrypto_destroyed_fails(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED})
	if err := k.CanPerformOriginatingCrypto(); err == nil {
		t.Error("CanPerformOriginatingCrypto on DESTROYED key: expected error, got nil")
	}
}

func TestKey_CanPerformOriginatingCrypto_compromised_fails(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED})
	if err := k.CanPerformOriginatingCrypto(); err == nil {
		t.Error("CanPerformOriginatingCrypto on COMPROMISED key: expected error, got nil")
	}
}

// CanPerformReceivingCrypto

func TestKey_CanPerformReceivingCrypto_active_succeeds(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_ACTIVE})
	if err := k.CanPerformReceivingCrypto(); err != nil {
		t.Errorf("CanPerformReceivingCrypto on ACTIVE key: unexpected error: %v", err)
	}
}

func TestKey_CanPerformReceivingCrypto_suspended_succeeds(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_SUSPENDED})
	if err := k.CanPerformReceivingCrypto(); err != nil {
		t.Errorf("CanPerformReceivingCrypto on SUSPENDED key: unexpected error: %v", err)
	}
}

func TestKey_CanPerformReceivingCrypto_deactivated_succeeds(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED})
	if err := k.CanPerformReceivingCrypto(); err != nil {
		t.Errorf("CanPerformReceivingCrypto on DEACTIVATED (legacy) key: unexpected error: %v", err)
	}
}

func TestKey_CanPerformReceivingCrypto_destroyed_fails(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED})
	if err := k.CanPerformReceivingCrypto(); err == nil {
		t.Error("CanPerformReceivingCrypto on DESTROYED key: expected error, got nil")
	}
}

func TestKey_CanPerformReceivingCrypto_destroyedCompromised_fails(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED})
	if err := k.CanPerformReceivingCrypto(); err == nil {
		t.Error("CanPerformReceivingCrypto on DESTROYED_COMPROMISED key: expected error, got nil")
	}
}

func TestKey_CanPerformReceivingCrypto_compromised_fails(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_COMPROMISED})
	if err := k.CanPerformReceivingCrypto(); err == nil {
		t.Error("CanPerformReceivingCrypto on COMPROMISED key: expected error, got nil")
	}
}

// TestKey_OriginatingVsReceiving_asymmetry verifies the core invariant:
// deactivated keys permit receiving operations (Verify/Decrypt/Unwrap) but not
// originating operations (Sign/Encrypt/Wrap).
func TestKey_OriginatingVsReceiving_asymmetry(t *testing.T) {
	k := key.NewKey(&storepb.Key{Status: types.KeyLifecycleState_KEY_LIFECYCLE_STATE_DEACTIVATED})
	if err := k.CanPerformOriginatingCrypto(); err == nil {
		t.Error("CanPerformOriginatingCrypto should fail on DEACTIVATED key")
	}
	if err := k.CanPerformReceivingCrypto(); err != nil {
		t.Errorf("CanPerformReceivingCrypto should succeed on DEACTIVATED key: %v", err)
	}
}
