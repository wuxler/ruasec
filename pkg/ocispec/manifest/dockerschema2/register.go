// Package dockerschema2 provides a type for parsing and serializing Docker Schema 2 manifest files.
package dockerschema2

import (
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
)

func init() {
	// register image manifest
	manifest.MustRegisterSchema(ocispec.MediaTypeDockerV2S2Manifest, UnmarshalImageManifest)
	// register manifest list
	manifest.MustRegisterSchema(ocispec.MediaTypeDockerV2S2ManifestList, UnmarshalManifestList)
}
