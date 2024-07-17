package remote

import (
	"context"
	"io"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/remote"
	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/util/xio/compression"
)

var _ ocispec.BlobLayer = (*remoteLayer)(nil)

type remoteLayer struct {
	client     *remote.Repository
	metadata   ocispec.LayerMetadata
	descriptor imgspecv1.Descriptor
}

// Metadata returns the metadata of the layer.
func (layer *remoteLayer) Metadata() ocispec.LayerMetadata {
	return layer.metadata
}

// Descriptor returns the descriptor for the resource.
func (layer *remoteLayer) Descriptor() imgspecv1.Descriptor {
	return layer.descriptor
}

// Compressed returns a reader that compressed what is read.
// The reader must be closed when reading is finished.
func (layer *remoteLayer) Compressed(ctx context.Context) (io.ReadCloser, error) {
	rc, err := layer.client.Blobs().Fetch(ctx, layer.descriptor)
	if err != nil {
		return nil, err
	}
	if layer.metadata.IsCompressed {
		return rc, nil
	}

	format, err := ocispec.CompressionFormatFromMediaType(layer.descriptor.MediaType)
	if err != nil {
		xio.CloseAndSkipError(rc)
		return nil, err
	}

	pr, pw := io.Pipe()
	// FIXME: support options?
	compressor, err := format.Compress(pw)
	if err != nil {
		xio.CloseAndSkipError(xio.MultiClosers(pw, pr, rc))
		return nil, err
	}

	// goroutine returns err so we can pw.CloseWithError(err)
	go func() {
		if _, err := io.Copy(compressor, rc); err != nil {
			defer xio.CloseAndSkipError(rc)
			defer xio.CloseAndSkipError(compressor)
			pw.CloseWithError(err)
			return
		}
		// close compressor writer to Flush it and write trailers
		if err := compressor.Close(); err != nil {
			pw.CloseWithError(err)
			return
		}

		defer rc.Close()
		defer compressor.Close()
	}()

	return pr, nil
}

// Uncompressed returns a reader that uncompresses what is read.
// The reader must be closed when reading is finished.
func (layer *remoteLayer) Uncompressed(ctx context.Context) (io.ReadCloser, error) {
	rc, err := layer.client.Blobs().Fetch(ctx, layer.descriptor)
	if err != nil {
		return nil, err
	}

	format, reader, err := compression.DetectReader(rc)
	if err != nil {
		xio.CloseAndSkipError(rc)
		return nil, err
	}

	uncompressor, err := format.Uncompress(reader)
	if err != nil {
		xio.CloseAndSkipError(rc)
		return nil, err
	}

	return xio.WrapReader(uncompressor, xio.MultiClosers(uncompressor, rc).Close), nil
}

func toLayers(layers []*remoteLayer) []ocispec.Layer {
	result := make([]ocispec.Layer, len(layers))
	for i, layer := range layers {
		result[i] = layer
	}
	return result
}
