package service

import (
	"context"

	messagespb "github.ibm.com/citius/citius-server/gen/go/api/messages"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
)

// KeyOrchestrator orchestrates key lifecycle workflows.
// Implementations coordinate template selection, provider dispatch, policy validation,
// and repository persistence crossing aggregate boundaries.
type KeyOrchestrator interface {
	CreateKey(ctx context.Context, spec core.KeyCreationSpec) (*KeyMetadata, error)

	// ReadKey returns the metadata for the named key at the given version.
	// Pass version=0 to read the current/latest version.
	ReadKey(ctx context.Context, keyName string, version uint32) (*KeyMetadata, error)
	ListKeys(ctx context.Context) ([]*KeyMetadata, error)
	DeleteKey(ctx context.Context, keyName string) error
	RotateKey(ctx context.Context, keyName string) (*KeyMetadata, error)
	SuspendKey(ctx context.Context, keyName string) error
	RestoreKey(ctx context.Context, keyName string) error
	DestroyKey(ctx context.Context, keyName string) error

	ImportKey(ctx context.Context, spec core.ImportKeySpec) (*KeyMetadata, error)

	// UpdateKeyPolicy changes the policy governing an existing key.
	// Policy changes take effect on the next crypto operation.
	// Returns ErrNotFound if the key does not exist.
	UpdateKeyPolicy(ctx context.Context, keyName string, policyName string) error

	TransformKey(ctx context.Context, spec TransformKeySpec) (*KeyMetadata, error)
}

type TransformKeySpec struct {
	KeyName            string
	ScopeSpecification *core.ScopeSpecification
	TemplateID         string
	RetainBytes        bool
}

func (s *TransformKeySpec) FromProto(ctx context.Context, protoReq *messagespb.TransformKeyRequest) error {
	const op = "service.(TransformKeySpec).FromProto"
	if protoReq == nil {
		return errors.New(ctx, op, errors.CodeInvalidArgument, "transform key request proto is nil")
	}
	res := &TransformKeySpec{
		KeyName:     protoReq.Name,
		RetainBytes: protoReq.RetainKeyBytes,
	}
	if protoReq.TemplateId != nil {
		res.TemplateID = *protoReq.TemplateId
	}
	if protoReq.ScopeSpec != nil {
		scopeSpec, err := core.ScopeSpecificationFromProto(ctx, protoReq.ScopeSpec)
		if err != nil {
			return errors.Wrap(ctx, op, err)
		}
		res.ScopeSpecification = scopeSpec
	}
	*s = *res
	return nil
}
