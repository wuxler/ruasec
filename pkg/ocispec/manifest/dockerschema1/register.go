package dockerschema1

import (
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
)

func init() {
	manifest.MustRegisterSchema(ocispec.MediaTypeDockerV2S1Manifest, UnmarshalImageManifest)
	manifest.MustRegisterSchema(ocispec.MediaTypeDockerV2S1SignedManifest, UnmarshalImageManifest)
	manifest.MustRegisterSchema("application/json", UnmarshalImageManifest)
	manifest.MustRegisterSchema("", UnmarshalImageManifest) // default schema
}
