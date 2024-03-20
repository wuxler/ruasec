package dockerschema2

import (
	"encoding/json"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image/manifest"
)

var (
	_ manifest.ImageManifest = (*DeserializedManifest)(nil)
)

// Manifest defines a docker version2 schema2 manifest.
type Manifest struct {
	manifest.Versioned

	// Config references the image configuration as a blob.
	Config imgspecv1.Descriptor `json:"config"`

	// Layers lists descriptors for the layers referenced by the
	// configuration.
	Layers []imgspecv1.Descriptor `json:"layers"`
}

// MediaType returns the media type of current manifest object.
func (m Manifest) MediaType() string {
	return m.Versioned.MediaType
}

// References returns a list of objects which make up this manifest.
// A reference is anything which can be represented by a imgspecv1.Descriptor.
// These can consist of layers, resources or other manifests.
//
// While no particular order is required, implementations should return
// them from highest to lowest priority. For example, one might want to
// return the base layer before the top layer.
func (m Manifest) References() []imgspecv1.Descriptor {
	references := make([]imgspecv1.Descriptor, 0, 1+len(m.Layers))
	references = append(references, m.Config)
	references = append(references, m.Layers...)
	return references
}

// DeserializedManifest wraps ManifestList with a copy of the original
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
