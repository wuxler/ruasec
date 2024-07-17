package remote

import (
	"context"
	"io"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/remote"
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
	panic("not implemented") // TODO: Implement
}

// Uncompressed returns a reader that uncompresses what is read.
// The reader must be closed when reading is finished.
func (layer *remoteLayer) Uncompressed(ctx context.Context) (io.ReadCloser, error) {
	panic("not implemented") // TODO: Implement
}

func toLayers(layers []*remoteLayer) []ocispec.Layer {
	result := make([]ocispec.Layer, len(layers))
	for i, layer := range layers {
		result[i] = layer
	}
	return result
}
