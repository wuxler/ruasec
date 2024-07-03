package ocispec

import imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

//go:generate mockgen -destination=./mocks/mock_manifest.go -package=mocks github.com/wuxler/ruasec/pkg/ocispec Manifest,IndexManifest

// Manifest represents a registry object specifying a set of references and an
// optional target.
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
