package template

import (
	"context"

	api "github.ibm.com/citius/citius-server/gen/go/types"
	"github.ibm.com/citius/citius-server/internal/core"
	"github.ibm.com/citius/citius-server/internal/errors"
	"google.golang.org/protobuf/proto"
)

// ParseScopeSpecification converts proto-encoded ScopeSpecification bytes
// into a core.ScopeSpec.
//
// This function lives in the template package because the template bounded
// context owns the mapping from proto ScopeSpecification (a deeply nested
// oneof with many primitive variants) to the domain-level core.ScopeSpec.
// The same mapping is used internally by Select, MatchesScope, and
// PrimaryScopeSpec — ParseScopeSpecification is the exported entry point
// for callers who receive scope data as proto wire bytes (e.g. the service
// layer deserializing core.KeyCreationSpec.Scope from a gRPC request).
//
// Returns an error if data is empty or not valid proto-encoded ScopeSpecification.
func ParseScopeSpecification(data []byte) (core.ScopeSpec, error) {
	const op errors.Op = "template.ParseScopeSpecification"
	if len(data) == 0 {
		return core.ScopeSpec{}, errors.New(context.TODO(), op, errors.CodeInvalidArgument,
			"scope specification bytes must not be empty")
	}
	spec := &api.ScopeSpecification{}
	if err := proto.Unmarshal(data, spec); err != nil {
		return core.ScopeSpec{}, errors.New(context.TODO(), op, errors.CodeInvalidArgument,
			"invalid scope specification: "+err.Error())
	}
	return scopeSpecFromProto(spec), nil
}
