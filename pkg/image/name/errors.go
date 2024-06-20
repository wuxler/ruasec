package name

import (
	"errors"
	"fmt"
)

var (
	// ErrBadName is an error for when a bad name is supplied.
	ErrBadName = errors.New("bad name")
	// ErrInvalidReference is an error for when an invalid reference is supplied.
	ErrInvalidReference = errors.New("invalid reference")
)

func newErr(err error, format string, args ...any) error {
	return errors.Join(err, fmt.Errorf(format, args...))
}

func newErrBadName(format string, args ...any) error {
	return newErr(ErrBadName, format, args...)
}

func newErrInvalidReference(format string, args ...any) error {
	return newErr(ErrInvalidReference, format, args...)
}
