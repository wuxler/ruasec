package dockerschema1

import (
	"time"

	"github.com/opencontainers/go-digest"

	"github.com/wuxler/ruasec/pkg/image/manifest"
)

// Manifest provides the base accessible fields for working with V2 image
// format in the registry.
//
// Deprecated: Docker Image Manifest v2, Schema 1 is deprecated since 2015.
// Use Docker Image Manifest v2, Schema 2, or the OCI Image Specification.
type Manifest struct {
	manifest.Versioned

	// Name is the name of the image's repository
	Name string `json:"name"`

	// Tag is the tag of the image specified by this manifest
	Tag string `json:"tag"`

	// Architecture is the host architecture on which this image is intended to
	// run
	Architecture string `json:"architecture"`

	// FSLayers is a list of filesystem layer blobSums contained in this image
	FSLayers []FSLayer `json:"fsLayers"`

	// History is a list of unstructured historical data for v1 compatibility
	History []History `json:"history"`
}

// FSLayer is a container struct for BlobSums defined in an image manifest.
//
// Deprecated: Docker Image Manifest v2, Schema 1 is deprecated since 2015.
// Use Docker Image Manifest v2, Schema 2, or the OCI Image Specification.
type FSLayer struct {
	// BlobSum is the tarsum of the referenced filesystem image layer
	BlobSum digest.Digest `json:"blobSum"`
}

// History stores unstructured v1 compatibility information.
//
// Deprecated: Docker Image Manifest v2, Schema 1 is deprecated since 2015.
// Use Docker Image Manifest v2, Schema 2, or the OCI Image Specification.
type History struct {
	// V1Compatibility is the raw v1 compatibility information
	V1Compatibility string `json:"v1Compatibility"`
}

// V1CompatibilityContainerConfig is a v1Compatibility container config in
// docker/distribution schema 1.
//
// Deprecated: Docker Image Manifest v2, Schema 1 is deprecated since 2015.
// Use Docker Image Manifest v2, Schema 2, or the OCI Image Specification.
type V1CompatibilityContainerConfig struct {
	Cmd []string
}

// V1Compatibility is a v1Compatibility in docker/distribution schema 1.
//
// Deprecated: Docker Image Manifest v2, Schema 1 is deprecated since 2015.
// Use Docker Image Manifest v2, Schema 2, or the OCI Image Specification.
type V1Compatibility struct {
	ID              string                         `json:"id"`
	Parent          string                         `json:"parent,omitempty"`
	Comment         string                         `json:"comment,omitempty"`
	Created         time.Time                      `json:"created"`
	ContainerConfig V1CompatibilityContainerConfig `json:"container_config,omitempty"`
	Author          string                         `json:"author,omitempty"`
	ThrowAway       bool                           `json:"throwaway,omitempty"`
}
