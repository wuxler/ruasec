package xfs

import (
	"errors"
	"io/fs"
)

// Generic errors
var (
	ErrIsNotDir = errors.New("is not a directory")
	ErrIsDir    = errors.New("is a directory")
)

// NewPathError returns a new *[fs.PathError].
func NewPathError(op string, path string, err error) error {
	return &fs.PathError{Op: op, Path: path, Err: err}
}
