// Package ocischema implements the OCI image manifest schema.
package ocischema

import (
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
)

func init() {
	// register image manifest
	manifest.MustRegisterSchema(ocispec.MediaTypeImageManifest, UnmarshalImageManifest)
	// register image index manifest
	manifest.MustRegisterSchema(ocispec.MediaTypeImageIndex, UnmarshalIndexManifest)
}
