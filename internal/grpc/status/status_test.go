package status

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	engerr "github.com/agile-crypto/citius-core/errors"
)

func TestToStatusError_Nil(t *testing.T) {
	if err := ToStatusError(nil); err != nil {
		t.Errorf("ToStatusError(nil) = %v; want nil", err)
	}
}

func TestToStatusError_KeyNotFound(t *testing.T) {
	ctx := context.Background()
	err := engerr.New(ctx, "test", engerr.CodeKeyNotFound, "key not found")
	st, ok := status.FromError(ToStatusError(err))
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %s", st.Code())
	}
}

func TestToStatusError_TemplateNotFound(t *testing.T) {
	ctx := context.Background()
	err := engerr.New(ctx, "test", engerr.CodeTemplateNotFound, "template not found")
	st, ok := status.FromError(ToStatusError(err))
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %s", st.Code())
	}
}

func TestToStatusError_PolicyViolation(t *testing.T) {
	ctx := context.Background()
	err := engerr.New(ctx, "test", engerr.CodePolicyViolation, "denied by policy")
	st, ok := status.FromError(ToStatusError(err))
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %s", st.Code())
	}
}

func TestToStatusError_AlreadyExists(t *testing.T) {
	ctx := context.Background()
	err := engerr.New(ctx, "test", engerr.CodeAlreadyExists, "already exists")
	st, ok := status.FromError(ToStatusError(err))
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.AlreadyExists {
		t.Errorf("expected AlreadyExists, got %s", st.Code())
	}
}

func TestToStatusError_NotImplemented(t *testing.T) {
	ctx := context.Background()
	err := engerr.New(ctx, "test", engerr.CodeNotImplemented, "not implemented")
	st, ok := status.FromError(ToStatusError(err))
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.Unimplemented {
		t.Errorf("expected Unimplemented, got %s", st.Code())
	}
}

func TestToStatusError_InvalidArgument(t *testing.T) {
	ctx := context.Background()
	err := engerr.New(ctx, "test", engerr.CodeInvalidArgument, "bad input")
	st, ok := status.FromError(ToStatusError(err))
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %s", st.Code())
	}
}

func TestToStatusError_UnknownError_ReturnsInternal(t *testing.T) {
	// A plain Go error (not *engerr.Error) must map to codes.Internal.
	plain := &plainError{"something unexpected"}
	st, ok := status.FromError(ToStatusError(plain))
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.Internal {
		t.Errorf("expected Internal, got %s", st.Code())
	}
}

// plainError is a minimal error type that is NOT *engerr.Error.
type plainError struct{ msg string }

func (e *plainError) Error() string { return e.msg }
