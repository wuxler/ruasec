// Package compression provides compress and uncompress operations.
package compression

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/samber/lo"

	"github.com/wuxler/ruasec/pkg/util/xio"
)

// ErrNoMatch is returned if there are no matching formats.
var ErrNoMatch = errors.New("no formats matched")

// Format represents either an archive or compression format.
type Format interface {
	// Name returns the name of the format.
	Name() string

	// Extensions returns the extensions associated with the format.
	Extensions() []string

	// Match returns whether the reader matched this format. If the error returned
	// is EOF, means that the input is too small.
	Match(r io.Reader) (bool, error)

	// MatchFilename returns whether the filename matches this format.
	MatchFilename(filename string) bool

	// Uncompress returns a reader for uncompressing the given reader.
	Uncompress(r io.Reader, opts ...Option) (io.ReadCloser, error)

	// Compress returns a writer for compressing the given writer.
	Compress(w io.Writer, opts ...Option) (io.WriteCloser, error)
}

// DetectReader iterates the registered formats and returns the one that matches
// the given io.Reader stream.
//
// If no matching formats were found, special error ErrNoMatch is returned.
//
// NOTE: The returned io.Reader will be always be non-nil and will read from the
// same point as the input reader; it should be used in place of the input reader
// after calling DetectReader because it preseves and re-reads the bytes that
// were already read during the detection process.
func DetectReader(input io.Reader) (Format, io.Reader, error) {
	rewindReader := xio.NewRewindReader(input)
	var errs []error
	var matched Format
	for name, format := range AllFormats() {
		ok, err := isFormatMatchReader(format, rewindReader)
		if err != nil {
			errs = append(errs, fmt.Errorf("matching format as %q error: %w", name, err))
			continue
		}
		if ok {
			matched = format
			break
		}
	}
	if matched == nil {
		errs = append([]error{ErrNoMatch}, errs...)
		return nil, rewindReader.Reader(), errors.Join(errs...)
	}
	return matched, rewindReader.Reader(), nil
}

func isFormatMatchReader(format Format, r *xio.RewindReader) (bool, error) {
	defer r.Rewind() // rewind for each format match call
	ok, err := format.Match(r)
	// if the error is EOF, we can just ignore it, means that the input is too small
	if err != nil && errors.Is(err, io.EOF) {
		return false, nil
	}
	return ok, err
}

// DetectFilename iterates the registered formats and returns the one that matches
// the given name matched.
//
// If no matching formats were found, special error ErrNoMatch is returned.
func DetectFilename(name string) (Format, error) {
	for _, format := range AllFormats() {
		if format.MatchFilename(name) {
			return format, nil
		}
	}
	return nil, ErrNoMatch
}

// MatchFilenameExtension returns true if the given filename matches any of the given extensions.
func MatchFilenameExtension(filename string, extensions ...string) bool {
	ext := filepath.Ext(filepath.Base(filename))
	_, ok := lo.Find(extensions, func(s string) bool {
		return strings.EqualFold(ext, s)
	})
	return ok
}
