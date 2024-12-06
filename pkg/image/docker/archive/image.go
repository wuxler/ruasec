package archive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"

	"github.com/opencontainers/image-spec/identity"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/util/xio/compression"
)

type archiveImage struct {
	archiveFS       fs.FS
	manifest        Manifest
	metadata        ocispec.ImageMetadata
	configFileBytes []byte

	// lazy load fields
	configFile *imgspecv1.Image
	layers     []*archiveLayer
}

// Metadata returns the metadata of the image.
func (img *archiveImage) Metadata() ocispec.ImageMetadata {
	return img.metadata
}

// ConfigFile returns the image config file bytes.
func (img *archiveImage) ConfigFile(_ context.Context) ([]byte, error) {
	if len(img.configFileBytes) > 0 {
		return img.configFileBytes, nil
	}
	return fs.ReadFile(img.archiveFS, img.manifest.Config)
}

// Layers returns a list of layer objects contained in the current image in order.
// The list order is from the oldest/base layer to the most-recent/top layer.
func (img *archiveImage) Layers(ctx context.Context) ([]ocispec.Layer, error) {
	if img.layers == nil {
		layers, err := img.loadLayers(ctx)
		if err != nil {
			return nil, err
		}
		img.layers = layers
	}
	result := make([]ocispec.Layer, len(img.layers))
	for i := range img.layers {
		result[i] = img.layers[i]
	}
	return result, nil
}

func (img *archiveImage) Close() error {
	return nil
}

func (img *archiveImage) loadLayers(ctx context.Context) ([]*archiveLayer, error) {
	configFile, err := img.parseConfigFile(ctx)
	if err != nil {
		return nil, err
	}

	// validate config file
	diffids := configFile.RootFS.DiffIDs
	if len(diffids) == 0 {
		return nil, errors.New("no layers found in image config file")
	}
	if len(diffids) != len(img.manifest.Layers) {
		return nil, fmt.Errorf("mismatch length of layers between image config file and archive manifest file: %d != %d", len(diffids), len(img.manifest.Layers))
	}

	// it will change the value of inputs in function [identity.ChainIDs], so we need to clone it
	chainids := identity.ChainIDs(slices.Clone(diffids))

	// filter out the empty layer history
	histories := []imgspecv1.History{}
	for _, history := range configFile.History {
		if history.EmptyLayer {
			continue
		}
		histories = append(histories, history)
	}
	if len(diffids) != len(histories) {
		return nil, fmt.Errorf("mismatch length of layers diffids and non-empty hisotries: %d != %d", len(diffids), len(histories))
	}

	// generate archive layer
	layers := make([]*archiveLayer, len(diffids))
	var parent *archiveLayer
	for i, layerPath := range img.manifest.Layers {
		fi, err := fs.Stat(img.archiveFS, layerPath)
		if err != nil {
			return nil, err
		}
		metadata := ocispec.LayerMetadata{
			DiffID:           diffids[i],
			ChainID:          chainids[i],
			IsCompressed:     false,
			UncompressedSize: fi.Size(),
			Parent:           parent,
			History:          &histories[i],
		}
		descriptor := imgspecv1.Descriptor{
			MediaType: ocispec.MediaTypeDockerV2S2ImageLayer,
			Digest:    diffids[i],
			Size:      fi.Size(),
			Platform:  &configFile.Platform,
		}
		layers[i] = &archiveLayer{
			archiveFS:  img.archiveFS,
			path:       layerPath,
			metadata:   metadata,
			descriptor: descriptor,
		}
	}
	return layers, nil
}

func (img *archiveImage) parseConfigFile(ctx context.Context) (*imgspecv1.Image, error) {
	if img.configFile != nil {
		return img.configFile, nil
	}

	configFileBytes, err := img.ConfigFile(ctx)
	if err != nil {
		return nil, err
	}
	configFile := &imgspecv1.Image{}
	if err := json.Unmarshal(configFileBytes, configFile); err != nil {
		return nil, err
	}
	img.configFile = configFile
	return img.configFile, nil
}

type archiveLayer struct {
	archiveFS  fs.FS
	path       string
	metadata   ocispec.LayerMetadata
	descriptor imgspecv1.Descriptor
}

// Metadata returns the metadata of the layer.
func (layer *archiveLayer) Metadata() ocispec.LayerMetadata {
	return layer.metadata
}

// Descriptor returns the descriptor for the resource.
func (layer *archiveLayer) Descriptor() imgspecv1.Descriptor {
	return layer.descriptor
}

// Compressed returns a reader that compressed what is read.
// The reader must be closed when reading is finished.
func (layer *archiveLayer) Compressed(_ context.Context) (io.ReadCloser, error) {
	rc, err := layer.archiveFS.Open(layer.path)
	if err != nil {
		return nil, err
	}
	format, _, err := compression.DetectReader(rc)
	if err != nil {
		xio.CloseAndSkipError(rc)
		return nil, err
	}
	pr, pw := io.Pipe()
	compressor, err := format.Compress(pw)
	if err != nil {
		xio.CloseAndSkipError(xio.MultiClosers(pw, pr, rc))
		return nil, err
	}

	// goroutine returns err so we can pw.CloseWithError(err)
	go func() error {
		defer xio.CloseAndSkipError(rc)
		if _, err := io.Copy(compressor, rc); err != nil {
			defer xio.CloseAndSkipError(compressor)
			return pw.CloseWithError(err)
		}
		// close compressor writer to flush it and write trailers
		if err := compressor.Close(); err != nil {
			return pw.CloseWithError(err)
		}
		return pw.Close()
	}() //nolint:errcheck // we don't care about the error here

	return pr, nil
}

// Uncompressed returns a reader that uncompresses what is read.
// The reader must be closed when reading is finished.
func (layer *archiveLayer) Uncompressed(ctx context.Context) (io.ReadCloser, error) {
	return layer.archiveFS.Open(layer.path)
}
