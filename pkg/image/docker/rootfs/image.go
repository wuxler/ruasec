package rootfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/util/xdocker/drivers"
	"github.com/wuxler/ruasec/pkg/util/xdocker/pathspec"
)

var _ ocispec.ImageCloser = (*rootfsImage)(nil)

// NewImage returns the image speicified by the name ref.
func NewImage(ctx context.Context, root string, ref string, opts ...image.ImageOption) (ocispec.ImageCloser, error) {
	storage, err := NewStorage(ctx, root)
	if err != nil {
		return nil, err
	}
	return storage.GetImage(ctx, ref, opts...)
}

type rootfsImage struct {
	metadata ocispec.ImageMetadata
	root     pathspec.DriverRoot
	layers   []*rootfsLayer

	// cached values

	configFileContent []byte
}

// Metadata returns the metadata of the image.
func (img *rootfsImage) Metadata() ocispec.ImageMetadata {
	return img.metadata
}

// ConfigFile returns the image config file bytes.
func (img *rootfsImage) ConfigFile(_ context.Context) ([]byte, error) {
	if len(img.configFileContent) > 0 {
		return img.configFileContent, nil
	}
	return img.root.ReadImageConfigBytes(img.metadata.ID)
}

// Layers returns a list of layer objects contained in the current image in order.
// The list order is from the oldest/base layer to the most-recent/top layer.
func (img *rootfsImage) Layers(_ context.Context) ([]ocispec.Layer, error) {
	layers := make([]ocispec.Layer, len(img.layers))
	for i, layer := range img.layers {
		layers[i] = layer
	}
	return layers, nil
}

// Close do nothing here
func (img *rootfsImage) Close() error {
	return nil
}

type rootfsLayer struct {
	chainid digest.Digest
	diffid  digest.Digest
	parent  *rootfsLayer
	cacheid string
	size    int64
	history *imgspecv1.History

	driver drivers.Driver
}

// SetHistory sets the history of the layer.
func (l *rootfsLayer) SetHistory(history *imgspecv1.History) {
	l.history = history
}

// Metadata returns the metadata of the layer.
func (l *rootfsLayer) Metadata() ocispec.LayerMetadata {
	return ocispec.LayerMetadata{
		DiffID:           l.diffid,
		ChainID:          l.chainid,
		UncompressedSize: l.size,
		Parent:           l.parent,
		History:          l.history,
	}
}

// GetFS returns a filesystem.
func (l *rootfsLayer) GetFS(ctx context.Context) (fs.FS, error) {
	if l.driver == nil {
		return nil, errors.New("storage driver is nil")
	}
	differ, ok := l.driver.(drivers.Differ)
	if !ok {
		return nil, fmt.Errorf("storage driver does not implement DifferDriver interface with type %T", l.driver)
	}
	getter, err := differ.Diff(l.cacheid)
	if err != nil {
		return nil, err
	}
	return getter.GetFS(ctx)
}
