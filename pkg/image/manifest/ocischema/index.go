package ocischema

import (
	"encoding/json"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image/manifest"
)

var (
	_ manifest.IndexManifest = (*DeserializedIndexManifest)(nil)
)

// IndexManifest wraps imgspecv1.Index.
type IndexManifest struct {
	imgspecv1.Index
}

// MediaType returns the media type of current manifest object.
func (m IndexManifest) MediaType() string {
	return m.Index.MediaType
}

// References returns the distribution descriptors for the referenced image
// manifests.
func (m IndexManifest) References() []imgspecv1.Descriptor {
	return m.Index.Manifests
}

// Manifests returns a list of all child manifest descriptors.
func (m IndexManifest) Manifests() []imgspecv1.Descriptor {
	return m.References()
}

// DeserializedIndexManifest wraps IndexManifest with a copy of the original
// JSON.
type DeserializedIndexManifest struct {
	IndexManifest

	// canonical is the canonical byte representation of the Manifest.
	canonical []byte
}

// UnmarshalJSON populates a new ManifestList struct from JSON data.
func (m *DeserializedIndexManifest) UnmarshalJSON(b []byte) error {
	m.canonical = make([]byte, len(b))
	// store manifest list in canonical
	copy(m.canonical, b)

	// Unmarshal canonical JSON into ManifestList object
	var shallow IndexManifest
	if err := json.Unmarshal(m.canonical, &shallow); err != nil {
		return err
	}
	if shallow.Index.MediaType == "" {
		shallow.Index.MediaType = manifest.MediaTypeImageIndex
	}

	m.IndexManifest = shallow

	return nil
}

// MarshalJSON returns the contents of canonical. If canonical is empty,
// marshals the inner contents.
func (m *DeserializedIndexManifest) MarshalJSON() ([]byte, error) {
	if len(m.canonical) > 0 {
		return m.canonical, nil
	}

	return nil, manifest.NewErrNotInitialized("canonical payload is empty")
}

// Payload returns the raw content of the manifest list. The contents can be
// used to calculate the content identifier.
func (m DeserializedIndexManifest) Payload() ([]byte, error) {
	return m.canonical, nil
}
