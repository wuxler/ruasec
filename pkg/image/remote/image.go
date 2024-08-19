package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/opencontainers/image-spec/identity"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution/remote"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/xlog"
)

var _ ocispec.ImageCloser = (*remoteImage)(nil)

// NewImage returns the image speicified by the parsed name.
func NewImage(ctx context.Context, client *remote.Registry, ref ocispecname.Reference, opts ...image.ImageOption) (ocispec.ImageCloser, error) {
	return NewStorage(client).GetImage(ctx, ref, opts...)
}

type remoteImage struct {
	client     *remote.Repository
	name       ocispecname.Reference
	manifest   manifest.ImageManifest
	descriptor imgspecv1.Descriptor
	metadata   ocispec.ImageMetadata

	// lazy initialized and cached properties
	configFileContent []byte
	layers            []*remoteLayer
}

// Metadata returns the metadata of the image.
func (img *remoteImage) Metadata() ocispec.ImageMetadata {
	return img.metadata
}

// ConfigFile returns the image config.
func (img *remoteImage) ConfigFile(ctx context.Context) ([]byte, error) {
	if img.configFileContent != nil {
		return img.configFileContent, nil
	}

	desc := img.manifest.Config()
	rc, err := img.client.Blobs().Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(rc)

	content, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	img.configFileContent = content

	img.configFileContent = content
	return img.configFileContent, nil
}

// Layers returns a list of layer objects contained in the current image in order.
// The list order is from the oldest/base layer to the most-recent/top layer.
func (img *remoteImage) Layers(ctx context.Context) ([]ocispec.Layer, error) {
	if img.layers != nil {
		return toLayers(img.layers), nil
	}

	// fetch and parse image config file
	configFile, err := img.ConfigFile(ctx)
	if err != nil {
		return nil, err
	}
	config := &imgspecv1.Image{}
	if err := json.Unmarshal(configFile, config); err != nil {
		return nil, err
	}

	// validate layers infos
	diffids := config.RootFS.DiffIDs
	if len(diffids) == 0 {
		return nil, errdefs.Newf(errdefs.ErrUnsupported, "no DiffIDs found in image config")
	}
	chainids := identity.ChainIDs(slices.Clone(diffids))
	if len(diffids) != len(chainids) {
		return nil, fmt.Errorf("mismatch length of DiffIDs and ChainIDs: %d != %d", len(diffids), len(chainids))
	}
	descriptors := manifest.NonEmptyLayers(img.manifest.Layers()...)
	if len(diffids) != len(descriptors) {
		return nil, fmt.Errorf("mismatch length of DiffIDs and Descriptors: %d != %d", len(diffids), len(descriptors))
	}

	var parent *remoteLayer
	var layers []*remoteLayer
	for i, diffid := range diffids {
		desc := descriptors[i]
		metadata := ocispec.LayerMetadata{
			DiffID:       diffid,
			ChainID:      chainids[i],
			Parent:       parent,
			IsCompressed: ocispec.IsCompressedBlob(desc.MediaType),
		}
		if metadata.IsCompressed {
			metadata.CompressedSize = desc.Size
		} else {
			metadata.UncompressedSize = desc.Size
		}
		current := &remoteLayer{
			client:     img.client,
			metadata:   metadata,
			descriptor: desc.Descriptor,
		}
		parent = current
		layers = append(layers, current)
	}

	histories := []imgspecv1.History{}
	for _, history := range config.History {
		if !history.EmptyLayer {
			histories = append(histories, history)
		}
	}
	if len(layers) != len(histories) {
		xlog.C(ctx).Warnf("skip, mismatch length of layers and non-empty hisotries: %d != %d", len(diffids), len(histories))
	} else {
		for i, layer := range layers {
			layer.metadata.History = &histories[i]
		}
	}

	img.layers = layers
	return toLayers(img.layers), nil
}

// Close releases any resources associated with the image.
func (img *remoteImage) Close() error {
	return nil
}

// Descriptor returns the descriptor for the resource.
func (img *remoteImage) Descriptor() imgspecv1.Descriptor {
	return img.descriptor
}
