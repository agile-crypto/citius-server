package key

import (
	"context"

	storepb "github.ibm.com/citius/citius-server/gen/go/store"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"google.golang.org/protobuf/proto"
)

// KeyVersion is the domain representation of one version of a Key's material.
// It belongs to the Key aggregate: key.Orchestrator creates and reads versions;
// external callers access material only through KeyOrchestrator.GetKeyWithMaterial.
type KeyVersion struct {
	stored *storepb.StoredKeyVersion
}

// NewVersion wraps a StoredKeyVersion.
func NewVersion(stored *storepb.StoredKeyVersion) *KeyVersion {
	if stored == nil {
		stored = &storepb.StoredKeyVersion{}
	}
	return &KeyVersion{stored: stored}
}

func (v *KeyVersion) StoredKeyVersion() *storepb.StoredKeyVersion { return v.stored }

func (v *KeyVersion) VersionNumber() uint32 { return v.stored.GetVersionNumber() }

// Callers should use Clone() before mutating.
func (v *KeyVersion) Clone() *KeyVersion {
	return &KeyVersion{stored: proto.Clone(v.stored).(*storepb.StoredKeyVersion)}
}

// VetForWrite validates the KeyVersion for the given storage operation.
func (v *KeyVersion) VetForWrite(ctx context.Context, op core.WriteOp) error {
	const opVet errors.Op = "key.(KeyVersion).VetForWrite"
	if op == core.OpCreate {
		if v.stored.GetVersionId() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "version_id is required")
		}
		if v.stored.GetKeyId() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "key_id is required")
		}
		if v.stored.GetProviderName() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "provider_name is required")
		}
	}
	return nil
}

// Compile-time assertion.
var _ core.VetForWriter = (*KeyVersion)(nil)
