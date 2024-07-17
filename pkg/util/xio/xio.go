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

// ReadAtMost reads at most n bytes from the stream. A nil, empty, or short
// stream is not an error. The returned slice of bytes may have length < n
// without an error.
func ReadAtMost(stream io.Reader, n int) ([]byte, error) {
	if stream == nil || n <= 0 {
		return []byte{}, nil
	}

	buf := make([]byte, n)
	nr, err := io.ReadFull(stream, buf)

	// Return the bytes read if there was no error OR if the
	// error was EOF (stream was empty) or UnexpectedEOF (stream
	// had less than n). We ignore those errors because we aren't
	// required to read the full n bytes; so an empty or short
	// stream is not actually an error.
	if err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return buf[:nr], nil
	}

	return nil, err
}
