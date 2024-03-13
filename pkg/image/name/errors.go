package name

import (
	"errors"
	"fmt"
)

var (
	// ErrBadName is an error for when a bad name is supplied.
	ErrBadName = errors.New("bad name")
)

func newErrBadName(format string, args ...any) error {
	return newErr(ErrBadName, format, args...)
}

func newErr(err error, format string, args ...any) error {
	return errors.Join(err, fmt.Errorf(format, args...))
}
