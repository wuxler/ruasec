package xio

import (
	"errors"
	"fmt"
	"io"
	"reflect"
)

const (
	_   = iota
	KiB = 1 << (10 * iota)
	MiB
	GiB
)

// IsNil checks for nil and nil interface.
func IsNil(i interface{}) bool {
	if i == nil {
		return true
	}
	refval := reflect.ValueOf(i)
	return refval.Kind() == reflect.Pointer && refval.IsNil()
}

// LimitCopy limits the copy from the reader. This is useful when extracting files from
// archives to protect against decompression bomb attacks.
func LimitCopy(w io.Writer, r io.Reader, limit int64) error {
	written, err := io.Copy(w, io.LimitReader(r, limit))
	if written >= limit || errors.Is(err, io.EOF) {
		return fmt.Errorf("size to read limit hit (potential decompression bomb attack): %d", limit)
	}
	return nil
}
