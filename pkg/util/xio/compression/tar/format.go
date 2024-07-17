package tar

import (
	"archive/tar"
	"io"
	"slices"

	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/util/xio/compression"
)

const (
	// FormatName is the type of the format.
	FormatName = "tar"
)

var (
	extensions = []string{".tar"}
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
	tr := tar.NewReader(r)
	_, err := tr.Next()
	return err == nil, err
}

// MatchFilename returns whether the filename matches this format.
func (f format) MatchFilename(filename string) bool {
	return compression.MatchFilenameExtension(filename, f.Extensions()...)
}

// Uncompress returns a reader for uncompressing the given reader.
func (f format) Uncompress(r io.Reader, _ ...compression.Option) (io.ReadCloser, error) {
	return xio.NopReader(r), nil
}

// Compress returns a writer for compressing the given writer.
func (f format) Compress(w io.Writer, _ ...compression.Option) (io.WriteCloser, error) {
	return xio.NopWriter(w), nil
}
