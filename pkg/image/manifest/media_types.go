package manifest

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
