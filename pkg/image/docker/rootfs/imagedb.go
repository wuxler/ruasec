package rootfs

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/opencontainers/go-digest"

	"github.com/wuxler/ruasec/pkg/util/xcontext"
	"github.com/wuxler/ruasec/pkg/util/xdocker/pathspec"
	"github.com/wuxler/ruasec/pkg/xlog"
)

var (
	supportedAlgorithms = []digest.Algorithm{
		digest.SHA256,
		// digest.SHA384, // Currently not used
		// digest.SHA512, // Currently not used
	}
)

func newImageDB(root pathspec.DriverRoot) *imageDB {
	return &imageDB{
		DriverRoot: root,
	}
}

type imageDB struct {
	DriverRoot pathspec.DriverRoot
}

func (db *imageDB) GetAllImageIDs(ctx context.Context) ([]digest.Digest, error) {
	ids := []digest.Digest{}
	dir := db.DriverRoot.ImageDBDir()
	for _, algorithm := range supportedAlgorithms {
		path := filepath.Join(dir, "content", algorithm.String())
		if err := xcontext.NonBlockingCheck(ctx, "readdir "+path); err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		for _, entry := range entries {
			if err := xcontext.NonBlockingCheck(ctx, "readdir "+path); err != nil {
				return nil, err
			}
			if !entry.Type().IsRegular() {
				continue
			}
			dgst := digest.NewDigestFromEncoded(algorithm, entry.Name())
			if err := dgst.Validate(); err != nil {
				xlog.C(ctx).With("path", filepath.Join(path, entry.Name())).Warnf(
					"skip, invalid image id with digest %s: %s", dgst.String(), err)
				continue
			}
			ids = append(ids, dgst)
		}
	}
	return ids, nil
}

func (db *imageDB) ReadImageConfig(id digest.Digest) ([]byte, error) {
	return db.DriverRoot.ReadImageConfigBytes(id)
}
