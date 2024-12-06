// Package archive provides a docker-archive storage implementation.
package archive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/go-digest/digestset"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/manifest"
	_ "github.com/wuxler/ruasec/pkg/ocispec/manifest/all"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xfs/tarfs"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

var _ image.Storage = (*Storage)(nil)

func init() {
	ocispecname.RegisterScheme(image.StorageTypeDockerArchive)
}

// NewStorageFromFile creates a new Storage from a tarball file.
func NewStorageFromFile(ctx context.Context, path string) (*Storage, error) {
	rc, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fsys, err := tarfs.New(ctx, rc)
	if err != nil {
		defer xio.CloseAndSkipError(rc)
		return nil, err
	}
	storage, err := NewStorage(ctx, fsys)
	if err != nil {
		defer xio.CloseAndSkipError(rc)
		return nil, err
	}
	storage.closer = rc
	return storage, nil
}

// NewStorage returns a new image storage with the given docker archive filesystem.
func NewStorage(ctx context.Context, fsys fs.FS) (*Storage, error) {
	archiveFS := NewArchiveFS(fsys)
	s := &Storage{
		archiveFS: archiveFS,
	}
	manifests, err := archiveFS.Manifest()
	if err != nil {
		return nil, err
	}
	s.manifestDB = newManifestDB(manifests...)
	return s, nil
}

// Storage is a image storage implementation for docker archive.
//
// NOTE: Since docker 1.25, docker archive transfers to OCI layout format.
// More to see:
//   - https://docs.docker.com/engine/release-notes/25.0/
//   - https://github.com/moby/moby/pull/44598
type Storage struct {
	archiveFS  *ArchiveFS
	manifestDB *manifestDB
	closer     io.Closer
}

// Type returns the unique identity type of the provider.
func (s *Storage) Type() string {
	return image.StorageTypeDockerArchive
}

// GetImage returns the image specified by ref.
//
// NOTE: The image must be closed when processing is finished.
func (s *Storage) GetImage(ctx context.Context, ref string, opts ...image.ImageOption) (ocispec.ImageCloser, error) {
	if strings.HasPrefix(ref, s.Type()) {
		ref = strings.TrimPrefix(ref, s.Type()+"://")
	}
	id, ok := s.manifestDB.LookupImageID(ref)
	if !ok {
		return nil, fmt.Errorf("%w: lookup image id with %s", errdefs.ErrNotFound, ref)
	}
	mf, ok := s.manifestDB.Get(id)
	if !ok {
		return nil, fmt.Errorf("%w: get manifest with image id %s", errdefs.ErrNotFound, id)
	}
	configFileBytes, err := fs.ReadFile(s.archiveFS, mf.Config)
	if err != nil {
		return nil, fmt.Errorf("unable to read image config file %s: %w", mf.Config, err)
	}
	configFile := &imgspecv1.Image{}
	if err := json.Unmarshal(configFileBytes, configFile); err != nil {
		return nil, fmt.Errorf("unable to unmarshal image config file %s: %w", mf.Config, err)
	}
	size := int64(0)
	for _, layerPath := range mf.Layers {
		fi, err := fs.Stat(s.archiveFS, layerPath)
		if err != nil {
			return nil, err
		}
		size += fi.Size()
	}
	metadata := ocispec.ImageMetadata{
		Name:             ref,
		ID:               id,
		RepoTags:         slices.Clone(mf.RepoTags),
		UncompressedSize: size,
		Platform:         &configFile.Platform,
	}

	img := &archiveImage{
		archiveFS:       s.archiveFS,
		manifest:        mf,
		metadata:        metadata,
		configFileBytes: configFileBytes,
		configFile:      configFile,
	}
	return img, nil
}

// Close closes the file wrapped in the storage.
func (s *Storage) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

func readJSONFile[T any](fsys fs.FS, path string, data *T) error {
	rc, err := fsys.Open(path)
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(rc)

	return json.NewDecoder(rc).Decode(data)
}

// Manifest defines the data structure in "manifest.json" file.
// Example:
//
//	{
//	  "Config": "blobs/sha256/8c86d514f886d9b2963a4718eeaf8268662a7e98038123211ef976cd748daedc",
//	  "RepoTags": [
//	    "alpine:3.18"
//	  ],
//	  "Layers": [
//	    "blobs/sha256/f9fc769d335082905a3e43c83f2a6d11b413556f9d156ab0fbe3166d256c0d99"
//	  ],
//	  "LayerSources": {
//	    "sha256:f9fc769d335082905a3e43c83f2a6d11b413556f9d156ab0fbe3166d256c0d99": {
//	      "mediaType": "application/vnd.oci.image.layer.v1.tar",
//	      "size": 7644160,
//	      "digest": "sha256:f9fc769d335082905a3e43c83f2a6d11b413556f9d156ab0fbe3166d256c0d99"
//	    }
//	  }
//	}
type Manifest struct {
	// Config is the path to image config file relative path.
	Config string `json:"Config"`

	// RepoTags is the list of image names.
	RepoTags []string `json:"RepoTags"`

	// Layers is the list of layer files relative path.
	Layers []string `json:"Layers"`

	// LayerSources is a map of layer sources descriptors.
	LayerSources map[string]imgspecv1.Descriptor `json:"LayerSources"`
}

func newManifestDB(manifests ...Manifest) *manifestDB {
	db := &manifestDB{
		names: make(map[string]digest.Digest),
		idmap: make(map[digest.Digest]int),
		idset: digestset.NewSet(),
	}
	for _, m := range manifests {
		db.Add(m)
	}
	return db
}

type manifestDB struct {
	manifests []Manifest
	names     map[string]digest.Digest // name -> image id
	idmap     map[digest.Digest]int    // image id -> index
	idset     *digestset.Set
}

func (db *manifestDB) Add(m Manifest) {
	db.manifests = append(db.manifests, m)
	index := len(db.manifests) - 1

	// NOTE: Legacy config field contains the ".json" file extension like
	// "8c86d514f886d9b2963a4718eeaf8268662a7e98038123211ef976cd748daedc".
	// Since docker 1.25, it was transferred to OCI layout and this field changes to
	// "blobs/sha256/8c86d514f886d9b2963a4718eeaf8268662a7e98038123211ef976cd748daedc".
	id := digest.Digest("sha256:" + strings.TrimSuffix(filepath.Base(m.Config), ".json"))
	db.idmap[id] = index
	_ = db.idset.Add(id) //nolint:errcheck // ignore error

	for _, name := range m.RepoTags {
		db.names[name] = id
	}
}

func (db *manifestDB) Get(id digest.Digest) (Manifest, bool) {
	index, ok := db.idmap[id]
	if !ok {
		return Manifest{}, false
	}
	return db.manifests[index], true
}

func (db *manifestDB) LookupImageID(ref string) (digest.Digest, bool) {
	if id, ok := db.names[ref]; ok {
		return id, true
	}
	var id digest.Digest
	if parsed, err := digest.Parse(ref); err == nil {
		id = parsed
	} else if parsed, err := digest.Parse("sha256:" + ref); err == nil {
		id = parsed
	} else if found, err := db.idset.Lookup(ref); err == nil {
		id = found
	}
	if id != "" {
		if _, ok := db.idmap[id]; ok {
			return id, true
		}
	}
	return "", false
}

// NewArchiveFS extends [fs.FS] for docker archive.
func NewArchiveFS(fsys fs.FS) *ArchiveFS {
	return &ArchiveFS{FS: fsys}
}

// ArchiveFS extends [fs.FS] for docker archive.
type ArchiveFS struct {
	fs.FS
}

// IsOCILayoutSupport checks if the docker archive is an OCI layout format.
//
// NOTE: Since docker 1.25, docker archive transfers to OCI layout format.
// More to see:
//   - https://docs.docker.com/engine/release-notes/25.0/
//   - https://github.com/moby/moby/pull/44598
func (fsys *ArchiveFS) IsOCILayoutSupport() bool {
	_, err := fs.Stat(fsys, "oci-layout")
	return err == nil
}

// Repositories reads the "repositories" file from the archive.
// The repositories file is a JSON map of repositories to a map of tags to digests.
// Format as REPOSITORY -> TAG -> DIGEST(without prefix "sha256:").
func (fsys *ArchiveFS) Repositories() (map[string]map[string]string, error) {
	var repositories map[string]map[string]string
	if err := readJSONFile(fsys, "repositories", &repositories); err != nil {
		return nil, err
	}
	return repositories, nil
}

// Manifest reads the "manifest.json" file from the archive.
func (fsys *ArchiveFS) Manifest() ([]Manifest, error) {
	var manifests []Manifest
	if err := readJSONFile(fsys, "manifest.json", &manifests); err != nil {
		return nil, err
	}
	return manifests, nil
}

// IndexJSON reads the "index.json" file from the archive.
func (fsys *ArchiveFS) IndexJSON() (ocispec.IndexManifest, error) {
	content, err := fs.ReadFile(fsys, imgspecv1.ImageIndexFile)
	if err != nil {
		return nil, err
	}
	mf, _, err := manifest.ParseBytes(content)
	if err != nil {
		return nil, err
	}
	index, ok := mf.(ocispec.IndexManifest)
	if !ok {
		return nil, errors.New("index.json is not an index manifest")
	}
	return index, nil
}

// OCILayout reads and returns the "oci-layout" file from the archive.
func (fsys *ArchiveFS) OCILayout() (*imgspecv1.ImageLayout, error) {
	var layout imgspecv1.ImageLayout
	if err := readJSONFile(fsys, imgspecv1.ImageLayoutFile, &layout); err != nil {
		return nil, err
	}
	return &layout, nil
}
