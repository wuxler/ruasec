package overlay2

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/afero"

	"github.com/wuxler/ruasec/pkg/util/xfile"
	"github.com/wuxler/ruasec/pkg/util/xfs"
	"github.com/wuxler/ruasec/pkg/util/xos"
	"github.com/wuxler/ruasec/pkg/xlog"
)

const (
	linkDir           = "l"
	linkFileName      = "link"
	diffDirName       = "diff"
	workDirName       = "work"
	mergedDirName     = "merged"
	lowerFile         = "lower"
	committedFileName = "committed"
)

var (
	_ xfs.Getter = (*entity)(nil)
)

type entity struct {
	*Driver
	cacheid string
}

// pathTo returns the path to {RootDir}/{Driver}/{cacheid}/{elem1}/{elem2}/...
func (ent *entity) pathTo(elems ...string) string {
	paths := append([]string{ent.Path(), ent.cacheid}, elems...)
	return filepath.Join(paths...)
}

// Path returns the path to directory {RootDir}/{Driver}/{cacheid}.
func (ent *entity) Path() string {
	return ent.pathTo()
}

// LowerFile returns the path to {RootDir}/{Driver}/{cacheid}/lower file.
func (ent *entity) LowerFile() string {
	return ent.pathTo(lowerFile)
}

// DiffDir returns the path to file {RootDir}/{Driver}/{cacheid}/diff.
func (ent *entity) DiffDir() string {
	return ent.pathTo(diffDirName)
}

// LinkFile returns the path to file {RootDir}/{Driver}/{cacheid}/link.
func (ent *entity) LinkFile() string {
	return ent.pathTo(linkDir, linkFileName)
}

// CommittedFile returns the path to file {RootDir}/{Driver}/{cacheid}/committed.
func (ent *entity) CommittedFile() string {
	return ent.pathTo(committedFileName)
}

// WorkDir returns the path to directory {RootDir}/{Driver}/{cacheid}/work.
func (ent *entity) WorkDir() string {
	return ent.pathTo(workDirName)
}

// MergedDir returns the path to directory {RootDir}/{Driver}/{cacheid}/merged.
func (ent *entity) MergedDir() string {
	return ent.pathTo(mergedDirName)
}

// LinkDir returns the path to directory {RootDir}/{Driver}/{cacheid}/l.
func (ent *entity) LinkDir() string {
	return ent.pathTo(linkDir)
}

// IsReadonly returns true if the driver is readonly. The file "committed" exists
// indicates the layer is readonly.
func (ent *entity) IsReadonly() (bool, error) {
	return xos.Exists(ent.CommittedFile())
}

// ReadLowerFile returns the content of the lower file.
func (ent *entity) ReadLowerFile() ([]byte, error) {
	path := ent.LowerFile()
	exists, err := xos.Exists(path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return os.ReadFile(path)
}

// GetLowerPaths reads the lower file and returns the list of lower paths.
func (ent *entity) GetLowerPaths() ([]string, error) {
	content, err := ent.ReadLowerFile()
	if err != nil {
		return nil, err
	}
	lowers := strings.Split(string(content), ":")
	lowerPaths := []string{}
	for _, lower := range lowers {
		// readlink absolute path: /var/lib/docker/overlay2/{s}, "s" here like "l/ZZEVNMYFSIQU3QWPGANYY5H"
		link, err := os.Readlink(ent.pathTo(lower))
		if err != nil {
			return nil, err
		}
		// link below "l" here like "../{id}/diff/" points to /var/lib/docker/overlay2/{id}/diff/
		lowerPath := filepath.Clean(ent.pathTo(linkDir, link))
		lowerPaths = append(lowerPaths, lowerPath)
	}
	return lowerPaths, nil
}

// GetFS returns the filesystem of the target.
func (ent *entity) GetFS(ctx context.Context) (fs.FS, error) {
	diffdir := ent.DiffDir()
	return &entityFS{
		ctx:     ctx,
		base:    diffdir,
		real:    os.DirFS(diffdir),
		virtual: afero.NewMemMapFs(),
	}, nil
}

// entityFS implements fs.FS and handle the whiteout file and directory path trans.
type entityFS struct {
	ctx     context.Context
	base    string
	real    fs.FS
	virtual afero.Fs
}

func (efsys *entityFS) fullpath(name string) string {
	return filepath.Join(efsys.base, name)
}

// Stat returns the FileInfo for the named file.
func (efsys *entityFS) Stat(name string) (fs.FileInfo, error) {
	fullpath := efsys.fullpath(name)
	fi, err := os.Lstat(fullpath)
	if err == nil {
		return fi, nil
	}
	vfi, verr := efsys.virtual.Stat(name)
	if verr == nil {
		return vfi, nil
	}
	return nil, fmt.Errorf("unable to stat: (real) %w; (virtual) %w", err, verr)
}

// Open returns a new file for reading the named file.
func (efsys *entityFS) Open(name string) (fs.File, error) {
	fi, err := efsys.Stat(name)
	if err != nil {
		return nil, err
	}

	// check file is a whiteout
	if fi.Mode()&fs.ModeCharDevice != 0 {
		if fi.Sys() != nil {
			if fisys, ok := fi.Sys().(*syscall.Stat_t); ok && fisys.Rdev/256 == 0 && fisys.Rdev%256 == 0 {
				// if whiteout, rename the file name with whiteout prefix and create a virtual one
				rename := filepath.Join(filepath.Dir(name), xfile.WhiteoutPrefix+filepath.Base(name))
				return efsys.virtual.Create(rename)
			}
		}
	}

	// check path is an opaque whiteout directory
	isOpaque, err := efsys.isOpaqueWhiteoutDir(name, fi)
	if err != nil {
		xlog.C(efsys.ctx).Warnf("unable to check if %s is an opaque whiteout dir: %s", name, err)
	}
	if isOpaque {
		// if the directory is an opaque whiteout and no virtual file exists,
		// create opaque whiteout file
		if xos.IsEmptyDir(efsys.fullpath(name)) {
			if err := efsys.virtual.MkdirAll(name, 0o755); err != nil { //nolint:gomnd // no magic number
				return nil, err
			}
			if _, err := efsys.virtual.Create(filepath.Join(name, xfile.OpaqueWhiteout)); err != nil {
				return nil, err
			}
		}
	}
	if realFile, err := efsys.real.Open(name); err == nil {
		return realFile, nil
	}
	return efsys.virtual.Open(name)
}

func (efsys *entityFS) isOpaqueWhiteoutDir(name string, fi fs.FileInfo) (bool, error) {
	if !fi.IsDir() {
		return false, nil
	}
	fullpath := efsys.fullpath(name)
	opaque, err := xos.Lgetxattr(fullpath, "trusted.overlay.opaque")
	if err != nil {
		return false, err
	}
	return string(opaque) == "y", nil
}
