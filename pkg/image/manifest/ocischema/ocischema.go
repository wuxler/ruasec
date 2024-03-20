// Package ocischema implements the OCI image manifest schema.
package ocischema

import (
	"fmt"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image/manifest"
)

func init() {
	// register image manifest
	manifest.MustRegisterSchema(manifest.MediaTypeImageManifest, UnmarshalImageManifest)
	// register image index manifest
	manifest.MustRegisterSchema(manifest.MediaTypeImageIndex, UnmarshalIndexManifest)
}

// UnmarshalImageManifest unmarshals an image manifest.
func UnmarshalImageManifest(b []byte) (manifest.Manifest, imgspecv1.Descriptor, error) {
	m := &DeserializedManifest{}
	if err := m.UnmarshalJSON(b); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}

	expect := manifest.MediaTypeImageManifest

	if m.MediaType() != expect {
		return nil, imgspecv1.Descriptor{}, fmt.Errorf(
			"mediaType in manifest list should be '%s' but got '%s'", expect, m.MediaType())
	}

	if err := manifest.ValidateUnambiguousManifestFormat(
		b,
		expect,
		manifest.AllowedFieldConfig|manifest.AllowedFieldLayers,
	); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}

	desc := imgspecv1.Descriptor{
		MediaType: expect,
		Size:      int64(len(b)),
		Digest:    digest.FromBytes(b),
	}

	return m, desc, nil
}

// UnmarshalIndexManifest unmarshals an image index manifest.
func UnmarshalIndexManifest(b []byte) (manifest.Manifest, imgspecv1.Descriptor, error) {
	m := &DeserializedIndexManifest{}
	if err := m.UnmarshalJSON(b); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}

	expect := manifest.MediaTypeImageIndex

	if m.MediaType() != expect {
		return nil, imgspecv1.Descriptor{}, fmt.Errorf(
			"mediaType in image index manifest should be '%s' but got '%s'",
			expect, m.MediaType())
	}

	if err := manifest.ValidateUnambiguousManifestFormat(
		b,
		expect,
		manifest.AllowedFieldManifests,
	); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}

	desc := imgspecv1.Descriptor{
		MediaType: expect,
		Size:      int64(len(b)),
		Digest:    digest.FromBytes(b),
	}

	return m, desc, nil
}
