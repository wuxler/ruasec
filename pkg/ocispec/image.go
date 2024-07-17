package ocispec

import (
	"context"
	"io"
	"io/fs"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Image defines the interface for an image.
//
// Images may originate from different storage backends and can be converted between them:
//   - remote: Retrieved using the OCI Distribution-defined interface by calling the image
//     repository's RESTful API
//   - docker-archive: Retrieved by parsing the tarball file generated by docker save
//   - docker-daemon: Retrieved through TCP communication with the Docker daemon
//   - docker-rootdir: Retrieved by directly accessing the filesystem where Docker stores
//     images (/var/lib/docker)
//   - oci-layout: Retrieved by accessing the filesystem of the [OCI Image Layout] directory
//   - oci-archive: Retrieved by parsing the archive file corresponding to the [OCI Image Layout]
//   - others: Refer to https://github.com/containers/image
//
// [OCI Image Layout]: https://github.com/opencontainers/image-spec/blob/main/image-layout.md
type Image interface {
	// Metadata returns the metadata of the image.
	Metadata() ImageMetadata

	// ConfigFile returns the image config file bytes.
	ConfigFile(ctx context.Context) ([]byte, error)

	// Layers returns a list of layer objects contained in the current image in order.
	// The list order is from the oldest/base layer to the most-recent/top layer.
	Layers(ctx context.Context) ([]Layer, error)
}

// ImageCloser declares an image object that requires resource release after use.
// The caller must invoke Close() to release resources after use.
//
// NOTE: Releasing resources here may refer to closing network connections,
// cleaning up temporary files, or closing file handles, etc.
type ImageCloser interface {
	Image
	io.Closer
}

// Layer is the minimal interface for an image layer.
type Layer interface {
	// Metadata returns the metadata of the layer.
	Metadata() LayerMetadata
}

// BlobLayer represents a Blob type Layer object obtained through the Image Manifest.
// It corresponds to the layer from a remote image or the layer from containerd.
type BlobLayer interface {
	Layer
	Describable
	Compressor
	Uncompressor
}

// FSLayer represents a file-system based Layer object.
type FSLayer interface {
	Layer
	DiffFS(ctx context.Context) (fs.FS, error)
}

// ImageMetadata represents the metadata of an image.
type ImageMetadata struct {
	// ID is the unique identifier of the image, which is the hash of the config file.
	ID digest.Digest `json:"id,omitempty" yaml:"id,omitempty"`

	// Name indicates the original reference name used to retrieve the current image,
	// which can be in the form of Repo:Tag, Repo@Digest, Image ID, or Partial Image ID.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// RepoTags lists all the aliases associated with the image in the Repo:Tag format.
	RepoTags []string `json:"repo_tags,omitempty" yaml:"repo_tags,omitempty"`

	// RepoDigests lists all the aliases associated with the image in the Repo@Digest format.
	RepoDigests []string `json:"repo_digests,omitempty" yaml:"repo_digests,omitempty"`

	// Digest is the hash of the image manifest corresponding to the current image
	// object when the manifest is of the index/manifest list type.
	Digest digest.Digest `json:"digest,omitempty" yaml:"digest,omitempty"`

	// IndexDigest is the sha256 hash of the original manifest, which could be an index/manifest
	// list type or an image manifest type.
	IndexDigest digest.Digest `json:"index_digest,omitempty" yaml:"index_digest,omitempty"`

	// Platform specifies the system platform information corresponding to the image.
	Platform *imgspecv1.Platform `json:"platform,omitempty" yaml:"platform,omitempty"`

	// CompressedSize represents the total compressed size of all the layers included in the image.
	CompressedSize int64 `json:"compressed_size,omitempty" yaml:"compressed_size,omitempty"`

	// UncompressedSize represents the total uncompressed size of all the layers included in the image.
	UncompressedSize int64 `json:"uncompressed_size,omitempty" yaml:"uncompressed_size,omitempty"`

	// IsCompressed indicates whether the current size is compressed.
	IsCompressed bool `json:"is_compressed,omitempty" yaml:"is_compressed,omitempty"`
}

// Size returns the size of the image, taking into account whether it is compressed.
func (m *ImageMetadata) Size() int64 {
	if m.IsCompressed {
		return m.CompressedSize
	}
	return m.UncompressedSize
}

// LayerMetadata defines the metadata of a layer.
type LayerMetadata struct {
	// DiffID is the hash of the tar file after the layer is decompressed, corresponding
	// to rootfs.DiffID in the image config.
	DiffID digest.Digest `json:"diff_id,omitempty" yaml:"diff_id,omitempty"`

	// ChainID returns the hash of the entire stack of DiffIDs from the bottom to the
	// current layer.
	//
	// NOTE:
	//   - ChainID(A) = DiffID(A)
	//   - ChainID(A|B) = sha256sum(ChainID(A) + " " + DiffID(B))
	//   - ChainID(A|B|C) = sha256sum(ChainID(A|B) + " " + DiffID(C))
	ChainID digest.Digest `json:"chain_id,omitempty" yaml:"chain_id,omitempty"`

	// IsCompressed indicates whether the current size is compressed.
	IsCompressed bool `json:"is_compressed,omitempty" yaml:"is_compressed,omitempty"`

	// CompressedSize represents the compressed size of the current layer.
	CompressedSize int64 `json:"compressed_size,omitempty" yaml:"compressed_size,omitempty"`

	// UncompressedSize represents the uncompressed size of the current layer.
	UncompressedSize int64 `json:"uncompressed_size,omitempty" yaml:"uncompressed_size,omitempty"`

	// Parent indicates the parent layer of the current layer. If the current layer has no
	// parent, it returns nil.
	Parent Layer `json:"-" yaml:"-"`

	// History indicates the build history information. It the history is not found, it returns nil.
	History *imgspecv1.History
}

// Size returns the size of the layer, taking into account whether it is compressed.
func (m *LayerMetadata) Size() int64 {
	if m.IsCompressed {
		return m.CompressedSize
	}
	return m.UncompressedSize
}
