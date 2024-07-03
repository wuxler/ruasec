// Package dockerschema1 provides a type for parsing and serializing Docker Schema 1 manifest files.
package dockerschema1

import (
	"fmt"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
)

// UnmarshalImageManifest parses a Docker Schema 1 manifest file.
func UnmarshalImageManifest(b []byte) (ocispec.Manifest, imgspecv1.Descriptor, error) {
	m := &SignedManifest{}
	if err := m.UnmarshalJSON(b); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}
	if m.SchemaVersion != 1 {
		return nil, imgspecv1.Descriptor{}, fmt.Errorf("schema version must be 1 but got %d", m.SchemaVersion)
	}
	expectMediaType := m.MediaType()
	if err := manifest.ValidateUnambiguousManifestFormat(
		b,
		expectMediaType,
		manifest.AllowedFieldFSLayers|manifest.AllowedFieldHistory,
	); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}
	desc := imgspecv1.Descriptor{
		MediaType: expectMediaType,
		Size:      int64(len(m.Canonical)),
		Digest:    digest.FromBytes(m.Canonical),
	}
	return m, desc, nil
}
