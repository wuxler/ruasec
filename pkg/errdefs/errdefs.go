// Package errdefs defines general error types and error operations.
package errdefs

import (
	"errors"
	"fmt"
)

// Newf wraps the base error and a formatted error created by fmt.Errorf,
// returns the error joined.
func Newf(base error, format string, args ...any) error {
	return errors.Join(base, fmt.Errorf(format, args...))
}

// NewE wraps the base error and the input error, returns the error joined.
func NewE(base error, err error) error {
	if err == nil || errors.Is(err, base) {
		return err
	}
	return errors.Join(base, err)
}
