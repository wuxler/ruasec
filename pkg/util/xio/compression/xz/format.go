package xz

import (
	"bytes"
	"io"
	"slices"

	fastxz "github.com/therootcompany/xz"
	"github.com/ulikunitz/xz"

	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/util/xio/compression"
)

const (
	FormatName = "xz"
)

var (
	// magic number at the beginning of xz files; see section 2.1.1.1
	// of https://tukaani.org/xz/xz-file-format.txt
	magicHeader = []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}
	extensions  = []string{".xz"}
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
func (format) Uncompress(r io.Reader, opts ...compression.Option) (io.ReadCloser, error) {
	xr, err := fastxz.NewReader(r, 0)
	if err != nil {
		return nil, err
	}
	return xio.NopReader(xr), err
}

// Compress returns a writer for compressing the given writer.
func (f format) Compress(w io.Writer, opts ...compression.Option) (io.WriteCloser, error) {
	return xz.NewWriter(w)
}
