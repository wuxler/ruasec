// Package dockerschema1 provides a type for parsing and serializing Docker Schema 1 manifest files.
package dockerschema1

import (
	"fmt"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image/manifest"
)

func init() {
	manifest.MustRegisterSchema(manifest.MediaTypeDockerV2S1Manifest, UnmarshalImageManifest)
	manifest.MustRegisterSchema(manifest.MediaTypeDockerV2S1SignedManifest, UnmarshalImageManifest)
	manifest.MustRegisterSchema("application/json", UnmarshalImageManifest)
	manifest.MustRegisterSchema("", UnmarshalImageManifest) // default schema
}

// UnmarshalImageManifest parses a Docker Schema 1 manifest file.
func UnmarshalImageManifest(b []byte) (manifest.Manifest, imgspecv1.Descriptor, error) {
	m := &SignedManifest{}
	if err := m.UnmarshalJSON(b); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}
	if m.SchemaVersion != 1 {
		return nil, imgspecv1.Descriptor{}, fmt.Errorf("schema version must be 1 but got %d", m.SchemaVersion)
	}
	expect := manifest.MediaTypeDockerV2S1SignedManifest
	if err := manifest.ValidateUnambiguousManifestFormat(
		b,
		expect,
		manifest.AllowedFieldFSLayers|manifest.AllowedFieldHistory,
	); err != nil {
		return nil, imgspecv1.Descriptor{}, err
	}
	desc := imgspecv1.Descriptor{
		MediaType: expect,
		Size:      int64(len(m.Canonical)),
		Digest:    digest.FromBytes(m.Canonical),
	}
	return m, desc, nil
}
