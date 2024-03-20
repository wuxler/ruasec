package manifest

import (
	"errors"
	"fmt"
)

var (
	// ErrNotInitialized is returned when an operation is attempted on a manifest
	// that has not been initialized.
	ErrNotInitialized = errors.New("not initialized")

	// ErrInvalidField is returned when an invalid field is encountered.
	ErrInvalidField = errors.New("invalid field")
)

// NewErrNotInitialized creates a new error with ErrNotInitialized as the root cause.
func NewErrNotInitialized(format string, args ...any) error {
	return errors.Join(ErrNotInitialized, fmt.Errorf(format, args...))
}

// NewErrInvalidField creates a new error with ErrInvalidField as the root cause.
func NewErrInvalidField(format string, args ...any) error {
	return errors.Join(ErrInvalidField, fmt.Errorf(format, args...))
}
