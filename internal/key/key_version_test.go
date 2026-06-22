package key_test

import (
	"context"
	"testing"

	storepb "github.ibm.com/citius/citius-server/gen/go/server/store"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/key"
)

func TestKeyVersion_VetForWrite_Create_happyPath(t *testing.T) {
	v := &key.Version{KeyVersion: &storepb.KeyVersion{
		PublicId:   "ver_01HXYZ",
		KeyId:      "key_01HXYZ",
		Version:    1,
		ProviderId: "software",
		Digest:     []byte("mac"),
	}}
	if err := v.VetForWrite(context.Background(), core.OpCreate); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestKeyVersion_VetForWrite_Create_missingKeyId(t *testing.T) {
	v := &key.Version{KeyVersion: &storepb.KeyVersion{
		PublicId:   "ver_01HXYZ",
		ProviderId: "software",
		Digest:     []byte("mac"),
	}}
	err := v.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing KeyId")
	}
}

func TestKeyVersion_VetForWrite_Create_missingProviderId(t *testing.T) {
	v := &key.Version{KeyVersion: &storepb.KeyVersion{
		PublicId: "ver_01HXYZ",
		KeyId:    "key_01HXYZ",
		Digest:   []byte("mac"),
	}}
	err := v.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing ProviderId")
	}
}

func TestKeyVersion_Clone_independent(t *testing.T) {
	original := &key.Version{KeyVersion: &storepb.KeyVersion{
		PublicId: "ver_01HXYZ",
		KeyId:    "key_01HXYZ",
	}}
	cloned := original.Clone()
	if original.KeyId != cloned.KeyId || original.PublicId != cloned.PublicId {
		t.Error("Clone() did not produce an independent copy — mutations alias the original")
	}
}

func TestKeyVersion_Version_accessor(t *testing.T) {
	v := &key.Version{KeyVersion: &storepb.KeyVersion{Version: 3}}
	if v.Version != 3 {
		t.Errorf("Version(): got %d want 3", v.GetVersion())
	}
}
