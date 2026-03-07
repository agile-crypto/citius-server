package key_test

import (
	"context"
	"testing"

	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/key"
)

func TestKeyVersion_VetForWrite_Create_happyPath(t *testing.T) {
	v := key.NewVersion(&storepb.StoredKeyVersion{
		VersionId:     "ver_01HXYZ",
		KeyId:         "key_01HXYZ",
		VersionNumber: 1,
		ProviderName:  "software",
		Hmac:          []byte("mac"),
	})
	if err := v.VetForWrite(context.Background(), core.OpCreate); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestKeyVersion_VetForWrite_Create_missingKeyId(t *testing.T) {
	v := key.NewVersion(&storepb.StoredKeyVersion{
		VersionId:    "ver_01HXYZ",
		ProviderName: "software",
		Hmac:         []byte("mac"),
	})
	err := v.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing KeyId")
	}
}

func TestKeyVersion_VetForWrite_Create_missingProviderName(t *testing.T) {
	v := key.NewVersion(&storepb.StoredKeyVersion{
		VersionId: "ver_01HXYZ",
		KeyId:     "key_01HXYZ",
		Hmac:      []byte("mac"),
	})
	err := v.VetForWrite(context.Background(), core.OpCreate)
	if err == nil {
		t.Fatal("expected error for missing ProviderName")
	}
}

func TestKeyVersion_Clone_independent(t *testing.T) {
	original := key.NewVersion(&storepb.StoredKeyVersion{
		VersionId: "ver_01HXYZ",
		KeyId:     "key_01HXYZ",
	})
	cloned := original.Clone()
	if original.StoredKeyVersion().KeyId != cloned.StoredKeyVersion().KeyId || original.StoredKeyVersion().VersionId != cloned.StoredKeyVersion().VersionId {
		t.Error("Clone() did not produce an independent copy — mutations alias the original")
	}
}

func TestKeyVersion_VersionNumber_accessor(t *testing.T) {
	v := key.NewVersion(&storepb.StoredKeyVersion{VersionNumber: 3})
	if v.VersionNumber() != 3 {
		t.Errorf("VersionNumber(): got %d want 3", v.VersionNumber())
	}
}
