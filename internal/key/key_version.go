package key

import (
	"context"
	"fmt"

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

// NewKeyVersion wraps a KeyVersion.
// TODO: Remove
func NewKeyVersion(stored *storepb.KeyVersion) *KeyVersion {
	if stored == nil {
		stored = &storepb.KeyVersion{}
	}
	return &KeyVersion{KeyVersion: stored}
}

func defaultKeyVersionId(keyId string, version uint32) string {
	return fmt.Sprintf("%s%s%d", keyId, versionSep, version)
}

func newKeyVersion(ctx context.Context, publicId, keyId, templateId, providerId string, version uint32, keyMaterial []byte, opt ...Option) (*KeyVersion, error) {
	const op = "key.newKeyVersion"
	opts := getOpts(opt...)
	if len(keyMaterial) == 0 {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "key material is required")
	}
	if providerId == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "provider ID is required")
	}
	if templateId == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "template ID is required")
	}
	if keyId == "" {
		return nil, errors.New(ctx, op, errors.CodeInvalidArgument, "key ID is required")
	}

	kv := &storepb.KeyVersion{
		PublicId:      publicId,
		KeyId:         keyId,
		Version:       version,
		ProviderId:    providerId,
		TemplateId:    templateId,
		KeyMaterial:   keyMaterial,
		WrappingKeyId: opts.withWrappingKeyId,
		Status:        opts.withStatus,
	}
	return NewKeyVersion(kv), nil

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
