package manifest

import (
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Parse parses manifest bytes with expect media type applied. Returns error if
// schema is not found in registers.
func Parse(mediaType string, content []byte) (Manifest, imgspecv1.Descriptor, error) {
	unmarshalFunc, err := GetSchema(mediaType)
	if err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}
	return unmarshalFunc(content)
}

// ParseBytes parses manifest bytes with no media type specified, will try
// to detect media type first before parsing.
func ParseBytes(content []byte) (Manifest, imgspecv1.Descriptor, error) {
	mt := DetectMediaType(content)
	m, desc, err := Parse(mt, content)
	if err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}
	return m, desc, nil
}

// Manifest represents a registry object specifying a set of
// references and an optional target.
type Manifest interface {
	// MediaType returns the media type of current manifest object.
	MediaType() string

	// References returns a list of objects which make up this manifest.
	// A reference is anything which can be represented by a imgspecv1.Descriptor.
	// These can consist of layers, resources or other manifests.
	//
	// While no particular order is required, implementations should return
	// them from highest to lowest priority. For example, one might want to
	// return the base layer before the top layer.
	References() []imgspecv1.Descriptor

	// Payload provides the serialized format of the manifest.
	Payload() ([]byte, error)
}

// IndexManifest extends Manifest when the raw manifest is an indexed type
// manifest that contains multiple child manifests.
type IndexManifest interface {
	Manifest

	// Manifests returns a list of all child manifest descriptors.
	Manifests() []imgspecv1.Descriptor
}

// ImageManifest extends Manifest when the raw manifest represents an image.
type ImageManifest interface {
	Manifest

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
