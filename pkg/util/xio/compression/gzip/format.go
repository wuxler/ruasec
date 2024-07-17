package gzip

import (
	"bytes"
	"io"
	"slices"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/pgzip"

	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/util/xio/compression"
)

const (
	// FormatName is the type of the format.
	FormatName = "gzip"
)

var (
	// magic number at the beginning of gzip files
	magicHeader = []byte{0x1f, 0x8b}
	extensions  = []string{".gz", ".tgz"}
)

func init() {
	compression.MustRegisterFormat(format{})
}

type format struct{}

// Name returns the name of the format.
func (f format) Name() string {
	return FormatName
}

// Extensions returns the extensions associated with the format.
func (f format) Extensions() []string {
	return slices.Clone(extensions)
}

// Match returns whether the reader matched this format. If the error returned
// is EOF, means that the input is too small.
func (f format) Match(r io.Reader) (bool, error) {
	buf, err := xio.ReadAtMost(r, len(magicHeader))
	if err != nil {
		return false, err
	}
	return bytes.Equal(buf, magicHeader), nil
}

// MatchFilename returns whether the filename matches this format.
func (f format) MatchFilename(filename string) bool {
	return compression.MatchFilenameExtension(filename, f.Extensions()...)
}

// Uncompress returns a reader for uncompressing the given reader.
func (f format) Uncompress(r io.Reader, opts ...compression.Option) (io.ReadCloser, error) {
	options := compression.MakeOptions(opts...).UncompressOptions()

	var rc io.ReadCloser
	var err error
	if options.Multithread {
		rc, err = pgzip.NewReader(r)
	} else {
		rc, err = gzip.NewReader(r)
	}
	return rc, err
}

// Compress returns a writer for compressing the given writer.
func (f format) Compress(w io.Writer, opts ...compression.Option) (io.WriteCloser, error) {
	options := compression.MakeOptions(opts...).CompressOptions()

	// assume default compression level if 0, rather than no
	// compression, since no compression on a gzipped file
	// doesn't make any sense in our use cases
	level := gzip.DefaultCompression
	if options.Level != nil {
		level = *options.Level
	}

	var wc io.WriteCloser
	var err error
	if options.Multithread {
		wc, err = pgzip.NewWriterLevel(w, level)
	} else {
		wc, err = gzip.NewWriterLevel(w, level)
	}
	return wc, err
}
