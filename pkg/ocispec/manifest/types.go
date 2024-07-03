package manifest

import (
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
)

//go:generate mockgen -destination=./types_mock_test.go -package=manifest_test github.com/wuxler/ruasec/pkg/ocispec/manifest ImageManifest

// Versioned provides a struct with the manifest schemaVersion and mediaType.
// Incoming content with unknown schema version can be decoded against this
// struct to check the version.
type Versioned struct {
	// SchemaVersion is the image manifest schema that this image follows
	SchemaVersion int `json:"schemaVersion"`

	// MediaType is the media type of this schema.
	MediaType string `json:"mediaType,omitempty"`
}

// ImageManifest extends Manifest when the raw manifest represents an image.
type ImageManifest interface {
	ocispec.Manifest

	// Config returns a descriptor of the separate image config blob.
	Config() imgspecv1.Descriptor

	// Layers returns a list of LayerDescriptors of layers referenced by the image.
	// Ordered from the root layer first (oldest) to the top layer at last (latest).
	Layers() []LayerDescriptor
}

// LayerDescriptor is an extended version of imgspecv1.Descriptor.
type LayerDescriptor struct {
	imgspecv1.Descriptor

	// Empty represents the layer is an "empty"/"throwaway" one, and may
	// or may not be physically represented in various source or storage
	// systems.
	//
	// False if the manifest type does not have the concept.
	Empty bool `json:"empty,omitempty"`
}

// NonEmptyLayers filters out empty layer descriptors. Main to skip empty blobs in
// docker v2 schema1 manifest.
func NonEmptyLayers(descriptors ...LayerDescriptor) []LayerDescriptor {
	clean := []LayerDescriptor{}
	for i := range descriptors {
		if descriptors[i].Empty {
			continue
		}
		clean = append(clean, descriptors[i])
	}
	return clean
}

// ImageSize sums all layer blobs size as the image compressed size.
func ImageSize(m ImageManifest) int64 {
	var size int64
	layers := NonEmptyLayers(m.Layers()...)
	for i := range layers {
		if layers[i].Size < 0 {
			continue
		}
		size += layers[i].Size
	}
	return size
}
