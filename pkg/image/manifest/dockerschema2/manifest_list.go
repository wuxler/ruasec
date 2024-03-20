package dockerschema2

import (
	"encoding/json"
	"errors"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image/manifest"
)

var (
	_ manifest.IndexManifest = (*DeserializedManifestList)(nil)
)

// ManifestList references manifests for various platforms.
type ManifestList struct {
	manifest.Versioned

	// Manifests references a list of manifests
	Manifests []ManifestDescriptor `json:"manifests"`
}

// MediaType returns the media type of current manifest object.
func (m ManifestList) MediaType() string {
	return m.Versioned.MediaType
}

// References returns the distribution descriptors for the referenced image
// manifests.
func (m ManifestList) References() []imgspecv1.Descriptor {
	dependencies := make([]imgspecv1.Descriptor, len(m.Manifests))
	for i := range m.Manifests {
		dependencies[i] = m.Manifests[i].Descriptor
		dependencies[i].Platform = &imgspecv1.Platform{
			Architecture: m.Manifests[i].Platform.Architecture,
			OS:           m.Manifests[i].Platform.OS,
			OSVersion:    m.Manifests[i].Platform.OSVersion,
			OSFeatures:   m.Manifests[i].Platform.OSFeatures,
			Variant:      m.Manifests[i].Platform.Variant,
		}
	}

	return dependencies
}

// DeserializedManifestList wraps ManifestList with a copy of the original
// JSON.
type DeserializedManifestList struct {
	ManifestList

	// canonical is the canonical byte representation of the Manifest.
	canonical []byte
}

// Manifests returns a list of all child manifest descriptors.
func (m DeserializedManifestList) Manifests() []imgspecv1.Descriptor {
	return m.References()
}

// UnmarshalJSON populates a new ManifestList struct from JSON data.
func (m *DeserializedManifestList) UnmarshalJSON(b []byte) error {
	m.canonical = make([]byte, len(b))
	// store manifest list in canonical
	copy(m.canonical, b)

	// Unmarshal canonical JSON into ManifestList object
	var shallow ManifestList
	if err := json.Unmarshal(m.canonical, &shallow); err != nil {
		return err
	}

	m.ManifestList = shallow

	return nil
}

// MarshalJSON returns the contents of canonical. If canonical is empty,
// marshals the inner contents.
func (m *DeserializedManifestList) MarshalJSON() ([]byte, error) {
	if len(m.canonical) > 0 {
		return m.canonical, nil
	}

	return nil, errors.New("JSON representation not initialized in DeserializedManifestList")
}

// Payload returns the raw content of the manifest list. The contents can be
// used to calculate the content identifier.
func (m DeserializedManifestList) Payload() ([]byte, error) {
	return m.canonical, nil
}

// ManifestDescriptor references a platform-specific manifest.
type ManifestDescriptor struct {
	imgspecv1.Descriptor

	// Platform specifies which platform the manifest pointed to by the
	// descriptor runs on.
	Platform PlatformSpec `json:"platform"`
}

// PlatformSpec specifies a platform where a particular image manifest is
// applicable.
//
// With additional `Features` field compared to imgspecv1.Platform
type PlatformSpec struct {
	// Architecture field specifies the CPU architecture, for example
	// `amd64` or `ppc64`.
	Architecture string `json:"architecture"`

	// OS specifies the operating system, for example `linux` or `windows`.
	OS string `json:"os"`

	// OSVersion is an optional field specifying the operating system
	// version, for example `10.0.10586`.
	OSVersion string `json:"os.version,omitempty"`

	// OSFeatures is an optional field specifying an array of strings,
	// each listing a required OS feature (for example on Windows `win32k`).
	OSFeatures []string `json:"os.features,omitempty"`

	// Variant is an optional field specifying a variant of the CPU, for
	// example `ppc64le` to specify a little-endian version of a PowerPC CPU.
	Variant string `json:"variant,omitempty"`

	// Features is an optional field specifying an array of strings, each
	// listing a required CPU feature (for example `sse4` or `aes`).
	Features []string `json:"features,omitempty"`
}
