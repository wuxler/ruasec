package zstd

import (
	"bytes"
	"io"
	"slices"

	"github.com/klauspost/compress/zstd"

	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/util/xio/compression"
)

const (
	// FormatName is the type of the format.
	FormatName = "zstd"
)

var (
	// magic number at the beginning of Zstandard files
	// https://github.com/facebook/zstd/blob/6211bfee5ec24dc825c11751c33aa31d618b5f10/doc/zstd_compression_format.md
	magicHeader = []byte{0x28, 0xb5, 0x2f, 0xfd}
	extensions  = []string{".zst"}
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
	decoderOptions := buildDecoderOptions(*options)
	zr, err := zstd.NewReader(r, decoderOptions...)
	if err != nil {
		return nil, err
	}
	return xio.WrapReader(zr, func() error {
		zr.Close()
		return nil
	}), nil
}

// Compress returns a writer for compressing the given writer.
func (f format) Compress(w io.Writer, opts ...compression.Option) (io.WriteCloser, error) {
	options := compression.MakeOptions(opts...).CompressOptions()
	encoderOptions := buildEncoderOptions(*options)
	return zstd.NewWriter(w, encoderOptions...)
}

func buildDecoderOptions(_ compression.UncompressOptions) []zstd.DOption {
	dOptions := []zstd.DOption{}
	return dOptions
}

func buildEncoderOptions(options compression.CompressOptions) []zstd.EOption {
	eOptions := []zstd.EOption{}

	level := zstd.SpeedDefault
	if options.Level != nil {
		level = normalizeEncoderLevel(*options.Level)
	}
	eOptions = append(eOptions, zstd.WithEncoderLevel(level))

	return eOptions
}

func normalizeEncoderLevel(level int) zstd.EncoderLevel {
	// map zstd compression levels to go-zstd levels
	// once we also have c based implementation move this to helper pkg
	if level < 0 {
		return zstd.SpeedDefault
	} else if level < 3 { //nolint:gomnd // zstd levels
		return zstd.SpeedFastest
	} else if level < 7 { //nolint:gomnd // zstd levels
		return zstd.SpeedDefault
	} else if level < 9 { //nolint:gomnd // zstd levels
		return zstd.SpeedBetterCompression
	}
	return zstd.SpeedBestCompression
}
