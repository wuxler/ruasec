package bz2

import (
	"bytes"
	"io"
	"slices"

	"github.com/dsnet/compress/bzip2"

	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/util/xio/compression"
)

const (
	FormatName = "bz2"
)

var (
	// magic number at the beginning of gzip files
	magicHeader = []byte("BZh")
	extensions  = []string{".bz2"}
)

func init() {
	compression.MustRegisterFormat(format{})
}

type format struct{}

// Name returns the name of the format.
func (format) Name() string {
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
func (f format) Uncompress(r io.Reader, _ ...compression.Option) (io.ReadCloser, error) {
	return bzip2.NewReader(r, nil)
}

// Compress returns a writer for compressing the given writer.
func (f format) Compress(w io.Writer, opts ...compression.Option) (io.WriteCloser, error) {
	options := compression.MakeOptions(opts...).CompressOptions()

	level := bzip2.DefaultCompression
	if options.Level != nil {
		level = *options.Level
	}

	return bzip2.NewWriter(w, &bzip2.WriterConfig{
		Level: level,
	})
}
