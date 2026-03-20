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
	*storepb.KeyVersion
}

// NewVersion wraps a KeyVersion.
func NewVersion(stored *storepb.KeyVersion) *KeyVersion {
	if stored == nil {
		stored = &storepb.KeyVersion{}
	}
	return &KeyVersion{KeyVersion: stored}
}

// Callers should use Clone() before mutating.
func (v *KeyVersion) Clone() *KeyVersion {
	return &KeyVersion{KeyVersion: proto.Clone(v.KeyVersion).(*storepb.KeyVersion)}
}

// VetForWrite validates the KeyVersion for the given storage operation.
func (v *KeyVersion) VetForWrite(ctx context.Context, op core.WriteOp) error {
	const opVet errors.Op = "key.(KeyVersion).VetForWrite"
	if op == core.OpCreate {
		if v.GetPublicId() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "version_id is required")
		}
		if v.GetKeyId() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "key_id is required")
		}
		if v.GetProviderId() == "" {
			return errors.New(ctx, opVet, errors.CodeInvalidArgument, "provider_id is required")
		}
	}
	return nil
}

// Compile-time assertion.
var _ core.VetForWriter = (*KeyVersion)(nil)
