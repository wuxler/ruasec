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
	"github.com/spf13/cast"

	"github.com/wuxler/ruasec/pkg/image/docker/rootfs"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/util/xdocker/pathspec"
	"github.com/wuxler/ruasec/pkg/util/xfile"
	"github.com/wuxler/ruasec/pkg/util/xos"
	"github.com/wuxler/ruasec/pkg/xlog"
)

func init() {
	rootfs.MustRegisterDriverCreator(
		rootfs.DriverTypeOverlay2,
		rootfs.DriverCreatorFunc(New),
	)
}

// New creates a new overlay2 driver
func New(ctx context.Context, dataRoot pathspec.DataRoot, options []string) (rootfs.Driver, error) {
	return &Driver{
		DriverRoot: dataRoot.DriverRoot(rootfs.DriverTypeOverlay2.String()),
	}, nil
}

// Driver is a driver for overlay2
type Driver struct {
	pathspec.DriverRoot
}

// Type returns the type of the driver
func (d *Driver) Type() rootfs.DriverType {
	return rootfs.DriverTypeOverlay2
}

// Accessible returns true when the target exists and accessible with the given cache id.
// If the target does not exist, it returns false with nil error.
// If the target is not accessible, it returns false with an error.
func (d *Driver) Accessible(cacheid string) (bool, error) {
	return xos.Exists(d.withTarget(cacheid).Path())
}

// GetMetadata returns the metadata of the target with the given cache id.
func (d *Driver) GetMetadata(cacheid string) (map[string]string, error) {
	target := d.withTarget(cacheid)
	readonly, err := target.IsReadonly()
	if err != nil {
		return nil, err
	}
	lowers, err := target.GetLowerPaths()
	if err != nil {
		return nil, err
	}
	metadata := map[string]string{
		"WorkDir":   target.WorkDir(),
		"MergedDir": target.MergedDir(),
		"UpperDir":  target.DiffDir(),
		"ReadOnly":  cast.ToString(readonly),
		"LowerDir":  strings.Join(lowers, ":"),
	}
	return metadata, nil
}

// GetDiffer returns a differ for the target with the given cache id.
func (d *Driver) GetDiffer(cacheid string) (ocispec.FSGetter, error) {
	return d.withTarget(cacheid), nil
}

func (d *Driver) withTarget(cacheid string) *targetDriver {
	return &targetDriver{
		Driver:  d,
		cacheid: cacheid,
	}
}

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
	_ ocispec.FSGetter = (*targetDriver)(nil)
)

type targetDriver struct {
	*Driver
	cacheid string
}

// pathTo returns the path to {RootDir}/{Driver}/{cacheid}/{elem1}/{elem2}/...
func (td *targetDriver) pathTo(elems ...string) string {
	paths := append([]string{td.Path(), td.cacheid}, elems...)
	return filepath.Join(paths...)
}

// Path returns the path to directory {RootDir}/{Driver}/{cacheid}.
func (td *targetDriver) Path() string {
	return td.pathTo()
}

// LowerFile returns the path to {RootDir}/{Driver}/{cacheid}/lower file.
func (td *targetDriver) LowerFile() string {
	return td.pathTo(lowerFile)
}

// DiffDir returns the path to file {RootDir}/{Driver}/{cacheid}/diff.
func (td *targetDriver) DiffDir() string {
	return td.pathTo(diffDirName)
}

// LinkFile returns the path to file {RootDir}/{Driver}/{cacheid}/link.
func (td *targetDriver) LinkFile() string {
	return td.pathTo(linkDir, linkFileName)
}

// CommittedFile returns the path to file {RootDir}/{Driver}/{cacheid}/committed.
func (td *targetDriver) CommittedFile() string {
	return td.pathTo(committedFileName)
}

// WorkDir returns the path to directory {RootDir}/{Driver}/{cacheid}/work.
func (td *targetDriver) WorkDir() string {
	return td.pathTo(workDirName)
}

// MergedDir returns the path to directory {RootDir}/{Driver}/{cacheid}/merged.
func (td *targetDriver) MergedDir() string {
	return td.pathTo(mergedDirName)
}

// LinkDir returns the path to directory {RootDir}/{Driver}/{cacheid}/l.
func (td *targetDriver) LinkDir() string {
	return td.pathTo(linkDir)
}

// IsReadonly returns true if the driver is readonly. The file "committed" exists
// indicates the layer is readonly.
func (td *targetDriver) IsReadonly() (bool, error) {
	return xos.Exists(td.CommittedFile())
}

// ReadLowerFile returns the content of the lower file.
func (td *targetDriver) ReadLowerFile() ([]byte, error) {
	path := td.LowerFile()
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
func (td *targetDriver) GetLowerPaths() ([]string, error) {
	content, err := td.ReadLowerFile()
	if err != nil {
		return nil, err
	}
	lowers := strings.Split(string(content), ":")
	lowerPaths := []string{}
	for _, lower := range lowers {
		// readlink absolute path: /var/lib/docker/overlay2/{s}, "s" here like "l/ZZEVNMYFSIQU3QWPGANYY5H"
		link, err := os.Readlink(td.pathTo(lower))
		if err != nil {
			return nil, err
		}
		// link below "l" here like "../{id}/diff/" points to /var/lib/docker/overlay2/{id}/diff/
		lowerPath := filepath.Clean(td.pathTo(linkDir, link))
		lowerPaths = append(lowerPaths, lowerPath)
	}
	return lowerPaths, nil
}

// GetFS returns the filesystem of the target.
func (td *targetDriver) GetFS(ctx context.Context) (fs.FS, error) {
	diffdir := td.DiffDir()
	return &targetFS{
		ctx:     ctx,
		base:    diffdir,
		real:    os.DirFS(diffdir),
		virtual: afero.NewMemMapFs(),
	}, nil
}

// targetFS implements fs.FS and handle the whiteout file and directory path trans.
type targetFS struct {
	ctx     context.Context
	base    string
	real    fs.FS
	virtual afero.Fs
}

func (tfsys *targetFS) fullpath(name string) string {
	return filepath.Join(tfsys.base, name)
}

// Stat returns the FileInfo for the named file.
func (tfsys *targetFS) Stat(name string) (fs.FileInfo, error) {
	fullpath := tfsys.fullpath(name)
	fi, err := os.Lstat(fullpath)
	if err == nil {
		return fi, nil
	}
	vfi, verr := tfsys.virtual.Stat(name)
	if verr == nil {
		return vfi, nil
	}
	return nil, fmt.Errorf("unable to stat: (real) %w; (virtual) %w", err, verr)
}

// Open returns a new file for reading the named file.
func (tfsys *targetFS) Open(name string) (fs.File, error) {
	fi, err := tfsys.Stat(name)
	if err != nil {
		return nil, err
	}

	// check file is a whiteout
	if fi.Mode()&fs.ModeCharDevice != 0 {
		if fi.Sys() != nil {
			if fisys, ok := fi.Sys().(*syscall.Stat_t); ok && fisys.Rdev/256 == 0 && fisys.Rdev%256 == 0 {
				// if whiteout, rename the file name with whiteout prefix and create a virtual one
				rename := filepath.Join(filepath.Dir(name), xfile.WhiteoutPrefix+filepath.Base(name))
				return tfsys.virtual.Create(rename)
			}
		}
	}

	// check path is an opaque whiteout directory
	isOpaque, err := tfsys.isOpaqueWhiteoutDir(name, fi)
	if err != nil {
		xlog.C(tfsys.ctx).Warnf("unable to check if %s is an opaque whiteout dir: %s", name, err)
	}
	if isOpaque {
		// if the directory is an opaque whiteout and no virtual file exists,
		// create opaque whiteout file
		if xos.IsEmptyDir(tfsys.fullpath(name)) {
			if err := tfsys.virtual.MkdirAll(name, 0o755); err != nil { //nolint:gomnd // no magic number
				return nil, err
			}
			if _, err := tfsys.virtual.Create(filepath.Join(name, xfile.OpaqueWhiteout)); err != nil {
				return nil, err
			}
		}
	}
	if realFile, err := tfsys.real.Open(name); err == nil {
		return realFile, nil
	}
	return tfsys.virtual.Open(name)
}

func (tfsys *targetFS) isOpaqueWhiteoutDir(name string, fi fs.FileInfo) (bool, error) {
	if !fi.IsDir() {
		return false, nil
	}
	fullpath := tfsys.fullpath(name)
	opaque, err := xos.Lgetxattr(fullpath, "trusted.overlay.opaque")
	if err != nil {
		return false, err
	}
	return string(opaque) == "y", nil
}
