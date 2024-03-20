package ocischema

import (
	"encoding/json"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image/manifest"
)

var (
	_ manifest.ImageManifest = (*DeserializedManifest)(nil)
)

// Manifest wraps imgspecv1.Manifest.
type Manifest struct {
	imgspecv1.Manifest
}

// MediaType returns the media type of current manifest object.
func (m Manifest) MediaType() string {
	return m.Manifest.MediaType
}

// References returns a list of objects which make up this manifest.
// A reference is anything which can be represented by a imgspecv1.Descriptor.
// These can consist of layers, resources or other manifests.
//
// While no particular order is required, implementations should return
// them from highest to lowest priority. For example, one might want to
// return the base layer before the top layer.
func (m Manifest) References() []imgspecv1.Descriptor {
	references := make([]imgspecv1.Descriptor, 0, 1+len(m.Manifest.Layers))
	references = append(references, m.Manifest.Config)
	references = append(references, m.Manifest.Layers...)
	return references
}

// DeserializedManifest wraps Manifest with a copy of the original
// JSON.
type DeserializedManifest struct {
	Manifest

	// canonical is the canonical byte representation of the Manifest.
	canonical []byte
}

// Config returns a descriptor of the separate image config blob.
func (m DeserializedManifest) Config() imgspecv1.Descriptor {
	return m.Manifest.Config
}

// Layers returns a list of LayerDescriptors of layers referenced by the image.
// Ordered from the root layer first (oldest) to the top layer at last (latest).
func (m DeserializedManifest) Layers() []manifest.LayerDescriptor {
	layers := []manifest.LayerDescriptor{}
	for _, desc := range m.Manifest.Layers {
		layers = append(layers, manifest.LayerDescriptor{
			Descriptor: desc,
			Empty:      false,
		})
	}
	return layers
}

// UnmarshalJSON populates a new ManifestList struct from JSON data.
func (m *DeserializedManifest) UnmarshalJSON(b []byte) error {
	m.canonical = make([]byte, len(b))
	// store manifest list in canonical
	copy(m.canonical, b)

	// Unmarshal canonical JSON into ManifestList object
	var shallow Manifest
	if err := json.Unmarshal(m.canonical, &shallow); err != nil {
		return err
	}
	if shallow.Manifest.MediaType == "" {
		shallow.Manifest.MediaType = manifest.MediaTypeImageManifest
	}
	m.Manifest = shallow

	return nil
}

// MarshalJSON returns the contents of canonical. If canonical is empty,
// marshals the inner contents.
func (m *DeserializedManifest) MarshalJSON() ([]byte, error) {
	if len(m.canonical) > 0 {
		return m.canonical, nil
	}

	return nil, manifest.NewErrNotInitialized("canonical payload is empty")
}

// Payload returns the raw content of the manifest list. The contents can be
// used to calculate the content identifier.
func (m DeserializedManifest) Payload() ([]byte, error) {
	return m.canonical, nil
}
