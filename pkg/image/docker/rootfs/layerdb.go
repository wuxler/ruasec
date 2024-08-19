package rootfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/opencontainers/go-digest"

	"github.com/wuxler/ruasec/pkg/util/xcontext"
	"github.com/wuxler/ruasec/pkg/util/xdocker/pathspec"
	"github.com/wuxler/ruasec/pkg/xlog"
)

func newLayerDB(root pathspec.DriverRoot) *layerDB {
	return &layerDB{
		DriverRoot: root,
		layers:     make(map[digest.Digest]*rootfsLayer),
	}
}

type layerDB struct {
	DriverRoot pathspec.DriverRoot

	// cached values

	layers map[digest.Digest]*rootfsLayer
	mu     sync.Mutex
}

// GetLayer returns the metadata for the layer with the given ChainID.
func (db *layerDB) GetLayer(driver Driver, chainid digest.Digest) (*rootfsLayer, error) {
	return db.loadLayer(driver, chainid)
}

// GetAllLayerChainIDs returns the ChainIDs of all layers in the layerdb directory.
func (db *layerDB) GetAllLayerChainIDs(ctx context.Context) ([]digest.Digest, error) {
	ids := []digest.Digest{}
	dir := db.DriverRoot.LayerDBDir()
	for _, algorithm := range supportedAlgorithms {
		path := filepath.Join(dir, algorithm.String())
		if err := xcontext.NonBlockingCheck(ctx, path); err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for _, entry := range entries {
			if err := xcontext.NonBlockingCheck(ctx, path); err != nil {
				return nil, err
			}
			if !entry.IsDir() || entry.Name() == "mounts" {
				continue
			}
			dgst := digest.NewDigestFromEncoded(algorithm, entry.Name())
			if err := dgst.Validate(); err != nil {
				xlog.C(ctx).With("path", filepath.Join(path, entry.Name())).Warnf(
					"skip, invalid layer chainid with digest %s: %s", dgst.String(), err)
				continue
			}
			ids = append(ids, dgst)
		}
	}
	return ids, nil
}

func (db *layerDB) loadLayer(driver Driver, chainid digest.Digest) (*rootfsLayer, error) {
	if err := db.DriverRoot.ValidateLayer(chainid); err != nil {
		db.mu.Lock()
		defer db.mu.Unlock()

		delete(db.layers, chainid)
		return nil, fmt.Errorf("invalid layer with chainid=%s: %w", chainid, err)
	}
	// fonud in cached
	db.mu.Lock()
	loaded, ok := db.layers[chainid]
	db.mu.Unlock()
	if ok {
		return loaded, nil
	}

	var errs []error
	diffid, err := db.DriverRoot.ReadLayerMetadataDiffID(chainid)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to read layer diffid: %w", err))
	}
	size, err := db.DriverRoot.ReadLayerMetadataSize(chainid)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to read layer size: %w", err))
	}
	cacheid, err := db.DriverRoot.ReadLayerMetadataCacheID(chainid)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to read layer cacheid: %w", err))
	}
	parent, err := db.DriverRoot.ReadLayerMetadataParent(chainid)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to read layer parent: %w", err))
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("unable to load layer with chainid=%s: %w", chainid, errors.Join(errs...))
	}
	layer := &rootfsLayer{
		chainid: chainid,
		diffid:  diffid,
		cacheid: cacheid,
		size:    size,
		driver:  driver,
	}
	if parent != "" {
		parentLayer, err := db.loadLayer(driver, parent)
		if err != nil {
			return nil, err
		}
		layer.parent = parentLayer
	}

	db.mu.Lock()
	db.layers[chainid] = layer
	db.mu.Unlock()

	return layer, nil
}
