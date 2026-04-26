// Package grpc provides gRPC handler adapters for the CaaS core.
// It is the boundary layer between the gRPC transport and the app.Service facade.
package grpc

import (
	stderrors "errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	engerr "github.ibm.com/citius/citius-server/internal/errors"
)

// ToStatusError converts a core error to a gRPC status error.
// Returns nil if err is nil.
// Uses engerr.GRPCCode for the code mapping — no duplication of the switch table.
func ToStatusError(err error) error {
	if err == nil {
		return nil
	}
	var e *engerr.Error
	if stderrors.As(err, &e) {
		return status.Error(engerr.GRPCCode(err), e.Message)
	}
	return status.Error(codes.Internal, err.Error())
}
