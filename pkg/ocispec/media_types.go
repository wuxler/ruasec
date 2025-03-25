package ocispec

import (
	"encoding/json"
	"fmt"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/util/xio/compression"
	"github.com/wuxler/ruasec/pkg/util/xio/compression/gzip"
	"github.com/wuxler/ruasec/pkg/util/xio/compression/tar"
	"github.com/wuxler/ruasec/pkg/util/xio/compression/zstd"
)

const (
	// DefaultMediaType is the media type used when no media type is specified.
	DefaultMediaType string = "application/octet-stream"
)

//////////////////////////////////////////////////////////////////////////
// OCI spec media types
//
// See https://github.com/opencontainers/image-spec/blob/v1.1.0/media-types.md
//
// Copy from https://github.com/opencontainers/image-spec/blob/v1.1.0/specs-go/v1/mediatype.go
//////////////////////////////////////////////////////////////////////////

const (
	// MediaTypeDescriptor specifies the media type for a content descriptor.
	MediaTypeDescriptor = "application/vnd.oci.descriptor.v1+json"

	// MediaTypeLayoutHeader specifies the media type for the oci-layout.
	MediaTypeLayoutHeader = "application/vnd.oci.layout.header.v1+json"

	// MediaTypeImageIndex specifies the media type for an image index.
	MediaTypeImageIndex = "application/vnd.oci.image.index.v1+json"

	// MediaTypeImageManifest specifies the media type for an image manifest.
	MediaTypeImageManifest = "application/vnd.oci.image.manifest.v1+json"

	// MediaTypeImageConfig specifies the media type for the image configuration.
	MediaTypeImageConfig = "application/vnd.oci.image.config.v1+json"

	// MediaTypeEmptyJSON specifies the media type for an unused blob containing the value "{}".
	MediaTypeEmptyJSON = "application/vnd.oci.empty.v1+json"
)

const (
	// MediaTypeImageLayer is the media type used for layers referenced by the manifest.
	MediaTypeImageLayer = "application/vnd.oci.image.layer.v1.tar"

	// MediaTypeImageLayerGzip is the media type used for gzipped layers
	// referenced by the manifest.
	MediaTypeImageLayerGzip = "application/vnd.oci.image.layer.v1.tar+gzip"

	// MediaTypeImageLayerZstd is the media type used for zstd compressed
	// layers referenced by the manifest.
	MediaTypeImageLayerZstd = "application/vnd.oci.image.layer.v1.tar+zstd"
)

// Non-distributable layer media-types.
//
// Deprecated: Non-distributable layers are deprecated, and not recommended
// for future use. Implementations SHOULD NOT produce new non-distributable
// layers.
// https://github.com/opencontainers/image-spec/pull/965
const (
	// MediaTypeImageLayerNonDistributable is the media type for layers referenced by
	// the manifest but with distribution restrictions.
	MediaTypeImageLayerNonDistributable = "application/vnd.oci.image.layer.nondistributable.v1.tar"

	// MediaTypeImageLayerNonDistributableGzip is the media type for
	// gzipped layers referenced by the manifest but with distribution
	// restrictions.
	MediaTypeImageLayerNonDistributableGzip = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"

	// MediaTypeImageLayerNonDistributableZstd is the media type for zstd
	// compressed layers referenced by the manifest but with distribution
	// restrictions.
	MediaTypeImageLayerNonDistributableZstd = "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"
)

//////////////////////////////////////////////////////////////////////////
// Docker spec media types
//////////////////////////////////////////////////////////////////////////

// V2 Schema2
// See https://docker-docs.uclv.cu/registry/spec/manifest-v2-2/
const (
	// MediaTypeDockerV2S2ManifestList specifies the mediaType for manifest lists.
	MediaTypeDockerV2S2ManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"

	// MediaTypeDockerV2S2Manifest specifies the mediaType for the current version.
	MediaTypeDockerV2S2Manifest = "application/vnd.docker.distribution.manifest.v2+json"

	// MediaTypeDockerV2S2ImageConfig specifies the mediaType for the image configuration.
	MediaTypeDockerV2S2ImageConfig = "application/vnd.docker.container.image.v1+json"

	// MediaTypeDockerV2S2ImageLayer is the mediaType used for layers which
	// are not compressed.
	MediaTypeDockerV2S2ImageLayer = "application/vnd.docker.image.rootfs.diff.tar"

	// MediaTypeDockerV2S2ImageLayerGzip is the mediaType used for layers referenced by the
	// manifest.
	MediaTypeDockerV2S2ImageLayerGzip = "application/vnd.docker.image.rootfs.diff.tar.gzip"

	// MediaTypeDockerV2S2ForeignImageLayer is used for schema 2 foreign layers, indicating
	// layers that must be downloaded from foreign URLs.
	MediaTypeDockerV2S2ForeignImageLayer = "application/vnd.docker.image.rootfs.foreign.diff.tar"

	// MediaTypeDockerV2S2ForeignImageLayerGzip is used for gzipped schema 2 foreign layers,
	// indicating layers that must be downloaded from foreign URLs.
	MediaTypeDockerV2S2ForeignImageLayerGzip = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"

	// MediaTypeDockerPluginConfig specifies the mediaType for plugin configuration.
	MediaTypeDockerPluginConfig = "application/vnd.docker.plugin.v1+json"
)

// V2 Schema1
// See https://docker-docs.uclv.cu/registry/spec/manifest-v2-1/
//
// NOTE: Docker Image Manifest v2, Schema 1 is deprecated since 2015.
// Use Docker Image Manifest v2, Schema 2, or the OCI Image Specification.
const (
	// MediaTypeDockerV2S1Manifest specifies the mediaType for the current version. Note
	// that for schema version 1, the the media is optionally "application/json".
	MediaTypeDockerV2S1Manifest = "application/vnd.docker.distribution.manifest.v1+json"

	// MediaTypeDockerV2S1SignedManifest specifies the mediatype for current SignedManifest version.
	MediaTypeDockerV2S1SignedManifest = "application/vnd.docker.distribution.manifest.v1+prettyjws"

	// MediaTypeDockerV2S1ManifestLayer specifies the media type for manifest layers.
	MediaTypeDockerV2S1ManifestLayer = "application/vnd.docker.container.image.rootfs.diff+x-gtar"
)

// DetectMediaType infers the manifest type from the given []byte and returns
// the corresponding media type. If the type is unknown or unrecognized, it
// returns an empty string.
//
// NOTE: Typically, we should directly obtain the media type externally rather
// than inferring it through parsing. However, there might be situations where
// it's not possible to obtain the manifest's media type externally, such as when
// the manifest is a local file.
func DetectMediaType(content []byte) string {
	// A subset of manifest fields; the rest is silently ignored by json.Unmarshal.
	// Also docker/distribution/manifest.Versioned.
	meta := struct {
		MediaType     string      `json:"mediaType"`
		SchemaVersion int         `json:"schemaVersion"`
		Signatures    interface{} `json:"signatures"`
	}{}
	if err := json.Unmarshal(content, &meta); err != nil {
		return ""
	}

	switch meta.MediaType {
	case MediaTypeDockerV2S2Manifest, MediaTypeDockerV2S2ManifestList,
		MediaTypeImageManifest, MediaTypeImageIndex: // A recognized type.
		return meta.MediaType
	}

	// this is the only way the function can return DockerV2Schema1MediaType,
	// and recognizing that is essential for stripping the JWS signatures = computing
	// the correct manifest digest.
	switch meta.SchemaVersion {
	case 1:
		if meta.Signatures != nil {
			return MediaTypeDockerV2S1SignedManifest
		}
		return MediaTypeDockerV2S1Manifest
	case 2: //nolint:mnd // skip magic number check
		// Best effort to understand if this is an OCI image since mediaType
		// wasn't in the manifest for OCI image-spec < 1.0.2.
		// For docker v2s2 meta.MediaType should have been set. But given the data,
		// this is our best guess.
		ociManifest := struct {
			Config struct {
				MediaType string `json:"mediaType"`
			} `json:"config"`
		}{}
		if err := json.Unmarshal(content, &ociManifest); err != nil {
			return ""
		}
		switch ociManifest.Config.MediaType {
		case MediaTypeImageConfig:
			return MediaTypeImageManifest
		case MediaTypeDockerV2S2ImageConfig:
			// This case should not happen since a Docker image must declare
			// a top-level media type and `meta.MediaType` has already been checked.
			return MediaTypeDockerV2S2Manifest
		}
		// Maybe an image index or an OCI artifact.
		ociIndex := struct {
			Manifests []imgspecv1.Descriptor `json:"manifests"`
		}{}
		if err := json.Unmarshal(content, &ociIndex); err != nil {
			return ""
		}
		if len(ociIndex.Manifests) != 0 {
			if ociManifest.Config.MediaType == "" {
				return MediaTypeImageIndex
			}
			// FIXME: this is mixing media types of manifests and configs.
			return ociManifest.Config.MediaType
		}
		// It's most likely an OCI artifact with a custom config media
		// type which is not (and cannot) be covered by the media-type
		// checks cabove.
		return MediaTypeImageManifest
	}
	return ""
}

// IsDockerSchema1Manifest returns true if the mediaType is docker schema1 manifest.
func IsDockerSchema1Manifest(mt string) bool {
	return mt == MediaTypeDockerV2S1Manifest || mt == MediaTypeDockerV2S1SignedManifest
}

// IsCompressedLayer returns true if the mediaType is a compressed blob type.
func IsCompressedBlob(mt string) bool {
	switch mt {
	case MediaTypeDockerV2S1ManifestLayer,
		MediaTypeDockerV2S2ImageLayerGzip,
		MediaTypeDockerV2S2ForeignImageLayerGzip,
		MediaTypeImageLayerGzip,
		MediaTypeImageLayerZstd,
		MediaTypeImageLayerNonDistributableGzip,
		MediaTypeImageLayerNonDistributableZstd:
		return true
	}
	return false
}

var (
	ociImageLayerMap = map[string]string{
		MediaTypeImageLayer:                     MediaTypeImageLayer,
		MediaTypeImageLayerGzip:                 MediaTypeImageLayerGzip,
		MediaTypeImageLayerZstd:                 MediaTypeImageLayerZstd,
		MediaTypeImageLayerNonDistributable:     MediaTypeImageLayerNonDistributable,
		MediaTypeImageLayerNonDistributableGzip: MediaTypeImageLayerNonDistributableGzip,
		MediaTypeImageLayerNonDistributableZstd: MediaTypeImageLayerNonDistributableZstd,

		MediaTypeDockerV2S1ManifestLayer: MediaTypeImageLayerGzip,

		MediaTypeDockerV2S2ImageLayer:            MediaTypeImageLayer,
		MediaTypeDockerV2S2ImageLayerGzip:        MediaTypeImageLayerGzip,
		MediaTypeDockerV2S2ForeignImageLayer:     MediaTypeImageLayerNonDistributable,
		MediaTypeDockerV2S2ForeignImageLayerGzip: MediaTypeImageLayerNonDistributableGzip,
	}
)

// CompressionFormatFromMediaType returns the compression format from the media type.
func CompressionFormatFromMediaType(mediaType string) (compression.Format, error) {
	converted := ociImageLayerMap[mediaType]
	switch converted {
	case MediaTypeImageLayer, MediaTypeImageLayerNonDistributable:
		return compression.GetFormat(tar.FormatName)
	case MediaTypeImageLayerGzip, MediaTypeImageLayerNonDistributableGzip:
		return compression.GetFormat(gzip.FormatName)
	case MediaTypeImageLayerZstd, MediaTypeImageLayerNonDistributableZstd:
		return compression.GetFormat(zstd.FormatName)
	default:
		return nil, fmt.Errorf("unsupported media type %q", mediaType)
	}
}
