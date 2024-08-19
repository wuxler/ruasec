package pathspec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/spf13/cast"
)

// DriverRoot represents the driver root directory.
type DriverRoot struct {
	root DataRoot
	name string
}

// String returns the string representation of the driver directory.
func (d DriverRoot) String() string {
	return d.Path()
}

// Path returns the path to the driver directory {RootDir}/{Driver},
// like /var/lib/docker/overlay2
func (d DriverRoot) Path() string {
	return d.root.pathTo(d.name)
}

// Name returns the driver name.
func (d DriverRoot) Name() string {
	return d.name
}

// DataRoot returns the path to docker data root directory.
func (d DriverRoot) DataRoot() DataRoot {
	return d.root
}

// ImageRootDir returns the path to the driver image directory {RootDir}/image/{Driver},
// like "/var/lib/docker/image/overlay2"
func (d DriverRoot) ImageRootDir() string {
	return filepath.Join(d.root.ImageDir(), d.name)
}

// ImageDBDir returns the path to image storage directory {RootDir}/image/{Driver}/imagedb,
// like "/var/lib/docker/image/overlay2/imagedb"
func (d DriverRoot) ImageDBDir() string {
	return filepath.Join(d.ImageRootDir(), "imagedb")
}

// LayerDBDir returns the path to layer storage directory {RootDir}/image/{Driver}/layerdb,
// like "/var/lib/docker/image/overlay2/layerdb"
func (d DriverRoot) LayerDBDir() string {
	return filepath.Join(d.ImageRootDir(), "layerdb")
}

// DistributionDir returns the path to distribution storage directory {RootDir}/image/{Driver}/distribution,
// like "/var/lib/docker/image/overlay2/distribution"
func (d DriverRoot) DistributionDir() string {
	return filepath.Join(d.ImageRootDir(), "distribution")
}

// RepositoryJSONFile returns the path to repository.json file {RootDir}/image/{Driver}/repositories.json,
// like "/var/lib/docker/image/overlay2/repositories.json"
func (d DriverRoot) RepositoryJSONFile() string {
	return filepath.Join(d.ImageRootDir(), "repositories.json")
}

// ImageConfigFile returns the path to {RootDir}/image/{Driver}/imagedb/content/{Algorithm}/{Hex}.
//
// NOTE: input digest is the image id which is the hash of the image config file.
func (d DriverRoot) ImageConfigFile(imageid digest.Digest) string {
	return filepath.Join(d.ImageDBDir(), "content", imageid.Algorithm().String(), imageid.Encoded())
}

// ImageMetadataDir returns the path to {RootDir}/image/{Driver}/imagedb/metadata/{Algorithm}/{Hex}.
//
// NOTE:
//   - input digest is the image id which is the hash of the image config file.
//   - directory MAY not exists
func (d DriverRoot) ImageMetadataDir(imageid digest.Digest) string {
	return filepath.Join(d.ImageDBDir(), "metadata", imageid.Algorithm().String(), imageid.Encoded())
}

// ImageMetadataDir returns the path to {RootDir}/image/{Driver}/imagedb/metadata/{Algorithm}/{Hex}/parent.
//
// NOTE:
//   - input digest is the image id which is the hash of the image config file.
//   - file MAY not exists
//   - content of the file is the image id of the parent image, like "sha256:b2dc3d737ff00f23ee00bc6587af5f592a04e0ccec8791d06c349a3f75f4d7d1"
func (d DriverRoot) ImageMetadataParentFile(imageid digest.Digest) string {
	return filepath.Join(d.ImageMetadataDir(imageid), "parent")
}

// ImageMetadataDir returns the path to {RootDir}/image/{Driver}/imagedb/metadata/{Algorithm}/{Hex}/lastUpdated.
//
// NOTE:
//   - input digest is the image id which is the hash of the image config file.
//   - file MAY not exists
//   - content of the file is the timestamp string format as time.RFC3339Nano, like "2022-12-21T21:30:30.965890471+08:00"
func (d DriverRoot) ImageMetadataLastUpdatedFile(imageid digest.Digest) string {
	return filepath.Join(d.ImageMetadataDir(imageid), "lastUpdated")
}

// LayerMetadataDir returns the path to {RootDir}/image/{Driver}/layerdb/{Algorithm}/{Hex}
//
// NOTE: input digest is the chain id of current layer.
func (d DriverRoot) LayerMetadataDir(chainid digest.Digest) string {
	return filepath.Join(d.LayerDBDir(), chainid.Algorithm().String(), chainid.Encoded())
}

// LayerMetadataSizeFile returns the path to {RootDir}/image/{Driver}/layerdb/{Algorithm}/{Hex}/size
//
// NOTE:
//   - input digest is the chain id of current layer.
//   - decompressed size, unit in "byte"
func (d DriverRoot) LayerMetadataSizeFile(chainid digest.Digest) string {
	return filepath.Join(d.LayerMetadataDir(chainid), "size")
}

// LayerMetadataParentFile returns the path to {RootDir}/image/{Driver}/layerdb/{Algorithm}/{Hex}/parent
//
// NOTE:
//   - input digest is the chain id of current layer.
//   - file MAY not exists
//   - content of the file is parent layer chainid
func (d DriverRoot) LayerMetadataParentFile(chainid digest.Digest) string {
	return filepath.Join(d.LayerMetadataDir(chainid), "parent")
}

// LayerMetadataDiffFile returns the path to {RootDir}/image/{Driver}/layerdb/{Algorithm}/{Hex}/diff
//
// NOTE:
//   - input digest is the chain id of current layer.
//   - content of the file is the diffid (hash of the decompressed archive file) of current layer
func (d DriverRoot) LayerMetadataDiffFile(chainid digest.Digest) string {
	return filepath.Join(d.LayerMetadataDir(chainid), "diff")
}

// LayerMetadataCacheIDFile returns the path to {RootDir}/image/{Driver}/layerdb/{Algorithm}/{Hex}/cache-id
//
// NOTE:
//   - input digest is the chain id of current layer.
//   - content of the file is the cache id in storage driver directory {RootDir}/{Driver}
func (d DriverRoot) LayerMetadataCacheIDFile(chainid digest.Digest) string {
	return filepath.Join(d.LayerMetadataDir(chainid), "cache-id")
}

// LayerMetadataTarSplitFile returns the path to {RootDir}/image/{Driver}/layerdb/{Algorithm}/{Hex}/tar-split.json.gz
//
// NOTE: input digest is the chain id of current layer.
func (d DriverRoot) LayerMetadataTarSplitFile(chainid digest.Digest) string {
	return filepath.Join(d.LayerMetadataDir(chainid), "tar-split.json.gz")
}

// ReadLayerMetadataDiffID returns the layer metadata DiffID with the given ChainID.
func (d DriverRoot) ReadLayerMetadataDiffID(chainid digest.Digest) (digest.Digest, error) {
	path := d.LayerMetadataDiffFile(chainid)
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	dgst, err := digest.Parse(strings.TrimSpace(string(content)))
	if err != nil {
		return "", err
	}
	return dgst, nil
}

// ReadLayerMetadataCacheID returns the layer metadata CacheID with the given ChainID.
func (d DriverRoot) ReadLayerMetadataCacheID(chainid digest.Digest) (string, error) {
	path := d.LayerMetadataCacheIDFile(chainid)
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	cacheid := strings.TrimSpace(string(content))
	if cacheid == "" {
		return "", fmt.Errorf("cache id is empty in %s", path)
	}
	return cacheid, nil
}

// ReadLayerMetadataParent returns the layer metadata parent ChainID with the given ChainID.
func (d DriverRoot) ReadLayerMetadataParent(chainid digest.Digest) (digest.Digest, error) {
	path := d.LayerMetadataParentFile(chainid)
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	parent, err := digest.Parse(strings.TrimSpace(string(content)))
	if err != nil {
		return "", err
	}
	return parent, nil
}

// ReadLayerMetadataSize returns the layer metadata Size with the given ChainID.
func (d DriverRoot) ReadLayerMetadataSize(chainid digest.Digest) (int64, error) {
	path := d.LayerMetadataSizeFile(chainid)
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	size, err := cast.ToInt64E(strings.TrimSpace(string(content)))
	if err != nil {
		return 0, err
	}
	return size, nil
}

// ValidateLayer validates the layer metadata directory with the given ChainID.
func (d DriverRoot) ValidateLayer(chainid digest.Digest) error {
	path := d.LayerMetadataDir(chainid)
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("layer metadata path must be a directory: %s", path)
	}
	return nil
}

// ReadImageConfigBytes returns the image config bytes with the given ImageID.
func (d DriverRoot) ReadImageConfigBytes(imageid digest.Digest) ([]byte, error) {
	path := d.ImageConfigFile(imageid)
	return os.ReadFile(path)
}

// ReadImageMetadataParent returns the parent ImageID with the given ImageID.
func (d DriverRoot) ReadImageMetadataParent(imageid digest.Digest) (digest.Digest, error) {
	path := d.ImageMetadataParentFile(imageid)
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("unable to read file path=%q: %w", path, err)
	}
	parent, err := digest.Parse(strings.TrimSpace(string(content)))
	if err != nil {
		return "", err
	}
	return parent, nil
}

// ReadImageMetadataLastUpdated returns the last updated time with the given ImageID.
func (d DriverRoot) ReadImageMetadataLastUpdated(imageid digest.Digest) (time.Time, error) {
	path := d.ImageMetadataLastUpdatedFile(imageid)
	content, err := os.ReadFile(path)
	var zero time.Time
	if err != nil {
		if os.IsNotExist(err) {
			return zero, nil
		}
		return zero, fmt.Errorf("unable to read file path=%q: %w", path, err)
	}
	str := strings.TrimSpace(string(content))
	if str != "" {
		return time.Parse(time.RFC3339Nano, str)
	}
	return zero, nil
}
