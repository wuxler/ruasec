package dockerschema2

import (
	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
)

// UnmarshalImageManifest parses a Docker image manifest from the given byte slice.
func UnmarshalImageManifest(b []byte) (ocispec.Manifest, imgspecv1.Descriptor, error) {
	m := &DeserializedManifest{}
	if err := m.UnmarshalJSON(b); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}

	expectMediaType := ocispec.MediaTypeDockerV2S2Manifest
	if err := manifest.ValidateUnambiguousManifestFormat(
		b,
		expectMediaType,
		manifest.AllowedFieldConfig|manifest.AllowedFieldLayers,
	); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}

	desc := imgspecv1.Descriptor{
		MediaType: expectMediaType,
		Size:      int64(len(b)),
		Digest:    digest.FromBytes(b),
	}

	return m, desc, nil
}

// UnmarshalManifestList parses a Docker image manifest list from the given byte slice.
func UnmarshalManifestList(b []byte) (ocispec.Manifest, imgspecv1.Descriptor, error) {
	m := &DeserializedManifestList{}
	if err := m.UnmarshalJSON(b); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}

	expectMediaType := ocispec.MediaTypeDockerV2S2ManifestList
	if err := manifest.ValidateUnambiguousManifestFormat(
		b,
		expectMediaType,
		manifest.AllowedFieldManifests,
	); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}

	desc := imgspecv1.Descriptor{
		MediaType: expectMediaType,
		Size:      int64(len(b)),
		Digest:    digest.FromBytes(b),
	}

	return m, desc, nil
}
