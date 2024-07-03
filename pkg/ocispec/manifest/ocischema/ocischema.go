package ocischema

import (
	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
)

// UnmarshalImageManifest unmarshals an image manifest.
func UnmarshalImageManifest(b []byte) (ocispec.Manifest, imgspecv1.Descriptor, error) {
	m := &DeserializedManifest{}
	if err := m.UnmarshalJSON(b); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}

	expectMediaType := ocispec.MediaTypeImageManifest
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

// UnmarshalIndexManifest unmarshals an image index manifest.
func UnmarshalIndexManifest(b []byte) (ocispec.Manifest, imgspecv1.Descriptor, error) {
	m := &DeserializedIndexManifest{}
	if err := m.UnmarshalJSON(b); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}

	expectMediaType := ocispec.MediaTypeImageIndex
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
