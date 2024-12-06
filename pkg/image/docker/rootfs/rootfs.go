package rootfs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/containerd/platforms"
	"github.com/opencontainers/image-spec/identity"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image"
	"github.com/wuxler/ruasec/pkg/ocispec"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	dockerdrivers "github.com/wuxler/ruasec/pkg/util/xdocker/drivers"
	_ "github.com/wuxler/ruasec/pkg/util/xdocker/drivers/register"
	"github.com/wuxler/ruasec/pkg/util/xdocker/pathspec"
	"github.com/wuxler/ruasec/pkg/xlog"
)

var _ image.Storage = (*Storage)(nil)

func init() {
	ocispecname.RegisterScheme(image.StorageTypeDockerFS)
}

// NewStorage returns a new storage for the given root directory.
func NewStorage(ctx context.Context, root string) (*Storage, error) {
	driverType := dockerdrivers.DetectType(ctx, root)
	if driverType == "" {
		return nil, errors.New("unable to detect storage type")
	}
	driver, err := dockerdrivers.New(ctx, root, driverType, dockerdrivers.DriverConfig{})
	if err != nil {
		return nil, fmt.Errorf("unable to create storage: %w", err)
	}

	driverRoot := pathspec.DataRoot(root).DriverRoot(driverType.String())
	storage := &Storage{
		root:    driverRoot,
		driver:  driver,
		imagedb: newImageDB(driverRoot),
		layerdb: newLayerDB(driverRoot),
		namedb:  newNameDB(driverRoot),
	}
	return storage, nil
}

// Storage is a storage for docker filesystem layout.
type Storage struct {
	root    pathspec.DriverRoot
	driver  dockerdrivers.Driver
	imagedb *imageDB
	layerdb *layerDB
	namedb  *nameDB
}

// Type returns the unique identity type of the provider.
func (s *Storage) Type() string {
	return image.StorageTypeDockerFS
}

// GetImage returns the image specified by ref.
//
// NOTE: The image must be closed when processing is finished.
func (s *Storage) GetImage(ctx context.Context, ref string, opts ...image.ImageOption) (ocispec.ImageCloser, error) {
	if strings.HasPrefix(ref, s.Type()) {
		ref = strings.TrimPrefix(ref, s.Type()+"://")
	}
	imageid, err := s.namedb.LookupImageID(ctx, ref)
	if err != nil {
		return nil, err
	}

	metadata := ocispec.ImageMetadata{
		Name: ref,
		ID:   imageid,
	}

	// load image metadata with aliased names and tags
	refs := s.namedb.ReferencesByImageID(imageid)
	for _, r := range refs {
		if _, ok := ocispecname.IsTagged(r); ok {
			metadata.RepoTags = append(metadata.RepoTags, r.String())
		}
		if _, ok := ocispecname.IsDigested(r); ok {
			metadata.RepoDigests = append(metadata.RepoDigests, r.String())
		}
	}

	// TODO: load image metadata with Digest from distribution database
	// directory, like "{DriverRoot}/distribution/"

	// load image config file
	configBytes, err := s.imagedb.ReadImageConfig(imageid)
	if err != nil {
		return nil, err
	}
	config := &imgspecv1.Image{}
	if err := json.Unmarshal(configBytes, config); err != nil {
		return nil, err
	}
	histories := []imgspecv1.History{}
	for _, history := range config.History {
		if !history.EmptyLayer {
			histories = append(histories, history)
		}
	}
	chainids := identity.ChainIDs(slices.Clone(config.RootFS.DiffIDs))

	historyMatched := (len(chainids) == len(histories))
	if !historyMatched {
		xlog.C(ctx).Warnf("skip, mismatch length of layers and non-empty hisotries: %d != %d",
			len(chainids), len(histories))
	}

	// load layers
	layers := make([]*rootfsLayer, len(chainids))
	for i, chainid := range chainids {
		layer, err := s.layerdb.GetLayer(s.driver, chainid)
		if err != nil {
			return nil, err
		}
		if historyMatched {
			layer.SetHistory(&histories[i])
		}

		layers[i] = layer
	}

	// sum up image size, default to uncompressed size
	for _, layer := range layers {
		metadata.UncompressedSize += layer.size
	}

	// set image platform from image config
	p := platforms.Normalize(config.Platform)
	metadata.Platform = &p

	// create image instance
	options := image.MakeImageOptions(opts...)
	options.ApplyMetadata(&metadata)
	img := &rootfsImage{
		metadata:          metadata,
		root:              s.root,
		layers:            layers,
		configFileContent: configBytes,
	}
	return img, nil
}

// Close closes the storage and releases resources.
func (s *Storage) Close() error {
	return nil
}
