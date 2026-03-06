// Package errors provides the structured error type for the core.
// All operations must return *Error (or nil), never fmt.Errorf or errors.New.
package errors

import (
	"context"
	"fmt"
)

// Op identifies an operation within the core using the format:
//
//	"package.(Type).Method"
//
// Example: "key.(Orchestrator).CreateKey"
type Op string

// Error is the core's structured error type.
type Error struct {
	Op      Op
	Code    Code
	Message string
	Wrapped error
}

// New creates a new Error. ctx is reserved for future tracing instrumentation.
func New(_ context.Context, op Op, code Code, msg string) *Error {
	return &Error{Op: op, Code: code, Message: msg}
}

// Wrap wraps an existing error, inheriting its Code if it is an *Error.
// Returns nil if err is nil.
func Wrap(_ context.Context, op Op, err error) *Error {
	if err == nil {
		return nil
	}
	code := CodeInternal
	var e *Error
	if As(err, &e) {
		code = e.Code
	}
	return &Error{Op: op, Code: code, Wrapped: err}
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Wrapped != nil {
		if e.Message != "" {
			return fmt.Sprintf("%s: %s: %v", e.Op, e.Message, e.Wrapped)
		}
		return fmt.Sprintf("%s: %v", e.Op, e.Wrapped)
	}
	return fmt.Sprintf("%s: %s", e.Op, e.Message)
}

// Unwrap returns the wrapped error for errors.Is / errors.As chaining.
func (e *Error) Unwrap() error {
	return e.Wrapped
}

// As is a convenience alias for the stdlib errors.As, typed to *Error.
func As(err error, target **Error) bool {
	// Use the stdlib function directly to avoid an import cycle.
	// This is the only place in internal/errors that touches stdlib errors.
	return stderrsAs(err, target)
}
