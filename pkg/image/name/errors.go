package name

import (
	"errors"
)

var (
	// ErrBadName is an error for when a bad name is supplied.
	ErrBadName = errors.New("bad name")
	// ErrInvalidReference is an error for when an invalid reference is supplied.
	ErrInvalidReference = errors.New("invalid reference")
)
