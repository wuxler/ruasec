package tarfs

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	stdpath "path"
	"slices"
	"sort"
	"strings"

	"github.com/wuxler/ruasec/pkg/util/xcontext"
	"github.com/wuxler/ruasec/pkg/util/xfs"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

var (
	_ fs.FS         = (*FS)(nil)
	_ fs.ReadDirFS  = (*FS)(nil)
	_ fs.ReadFileFS = (*FS)(nil)
	_ fs.GlobFS     = (*FS)(nil)
	_ fs.SubFS      = (*FS)(nil)
)

// Reader defines the minimal reader interface to create a [fs.FS] for the tarball archive.
type Reader interface {
	io.ReadSeeker
	io.ReaderAt
}

// New creates a new *FS with the given Reader.
func New(ctx context.Context, r Reader) (*FS, error) {
	tfs := &FS{
		reader: r,
		inodes: make(map[string]*inode),
	}
	tfs.inodes["."] = &inode{
		DirEntry: fs.FileInfoToDirEntry(xfs.NewFakeDirFileInfo(".")),
	}

	sequence := int64(-1)
	tr := tar.NewReader(r)
	for {
		if err := xcontext.NonBlockingCheck(ctx, "iterating tar reader aborted"); err != nil {
			return nil, err
		}

		// TODO: support progress bar callback
		sequence++

		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if hdr == nil {
			continue
		}
		name := stdpath.Clean(hdr.Name)
		if name == "." {
			continue
		}
		offset, err := r.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("unable to read current seek offset: %w", err)
		}
		node := &inode{
			DirEntry: fs.FileInfoToDirEntry(hdr.FileInfo()),
			header:   hdr,
			offset:   offset,
			sequence: sequence,
		}
		tfs.append(name, node)
	}
	// sort childrens
	for _, node := range tfs.inodes {
		sort.SliceStable(node.childrens, func(i, j int) bool {
			return node.childrens[i].Name() < node.childrens[j].Name()
		})
	}
	return tfs, nil
}

type inode struct {
	fs.DirEntry
	childrens []fs.DirEntry

	header   *tar.Header
	offset   int64
	sequence int64
}

// FS is a file system that generated from tarball archive.
type FS struct {
	reader Reader
	inodes map[string]*inode
}

func (fsys *FS) append(name string, node *inode) {
	fsys.inodes[name] = node
	dir := stdpath.Dir(name)
	if parent, ok := fsys.inodes[dir]; ok {
		parent.childrens = append(parent.childrens, node)
		return
	}
	fakeDirNode := &inode{DirEntry: fs.FileInfoToDirEntry(xfs.NewFakeDirFileInfo(name))}
	fsys.append(dir, fakeDirNode)

	fakeDirNode.childrens = append(fakeDirNode.childrens, node)
}

func (fsys *FS) get(op, name string) (*inode, error) {
	if !fs.ValidPath(name) {
		return nil, xfs.NewPathError(op, name, fs.ErrInvalid)
	}
	clean := stdpath.Clean(name)
	node, ok := fsys.inodes[clean]
	if !ok {
		return nil, xfs.NewPathError(op, name, fs.ErrNotExist)
	}
	return node, nil
}

// Open opens the named file.
// Implements the [fs.FS] interface.
func (fsys *FS) Open(name string) (fs.File, error) {
	node, err := fsys.get("open", name)
	if err != nil {
		return nil, err
	}
	// FIXME(wuxler): Should we handle symlink node here?
	size := int64(0)
	if node.header != nil {
		size = node.header.Size
	}
	file := &entry{
		inode:  node,
		reader: io.NewSectionReader(fsys.reader, node.offset, size),
	}
	return file, nil
}

// ReadDir reads the named directory and returns a list of directory entries sorted by filename.
// Implements the [fs.ReadDirFS] interface.
func (fsys *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	node, err := fsys.get("readdir", name)
	if err != nil {
		return nil, err
	}
	if !node.IsDir() {
		return nil, xfs.NewPathError("readdir", name, xfs.ErrIsNotDir)
	}
	return slices.Clone(node.childrens), nil
}

// ReadFile reads the named file and returns its contents.
// Implements the [fs.ReadFileFS] interface.
func (fsys *FS) ReadFile(name string) ([]byte, error) {
	node, err := fsys.get("readfile", name)
	if err != nil {
		return nil, err
	}
	if node.IsDir() {
		return nil, xfs.NewPathError("readfile", name, xfs.ErrIsDir)
	}
	rc, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(rc)

	return io.ReadAll(rc)
}

// Stat returns a [fs.FileInfo] describing the file.
// Implements the [fs.StatFS] interface.
func (fsys *FS) Stat(name string) (fs.FileInfo, error) {
	node, err := fsys.get("stat", name)
	if err != nil {
		return nil, err
	}
	return node.Info()
}

// Glob returns the names of all files matching pattern.
// Implements the [fs.GlobFS] interface.
func (fsys *FS) Glob(pattern string) ([]string, error) {
	matches := []string{}
	for name := range fsys.inodes {
		matched, err := stdpath.Match(pattern, name)
		if err != nil {
			return nil, err
		}
		if matched {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	return matches, nil
}

// Sub returns an FS corresponding to the subtree rooted at dir.
// Implements the [fs.SubFS] interface.
func (fsys *FS) Sub(dir string) (fs.FS, error) {
	dir = stdpath.Clean(dir)
	if dir == "." {
		return fsys, nil
	}
	node, err := fsys.get("sub", dir)
	if err != nil {
		return nil, err
	}
	if !node.IsDir() {
		return nil, xfs.NewPathError("sub", dir, xfs.ErrIsNotDir)
	}
	subfs := &FS{
		reader: fsys.reader,
		inodes: make(map[string]*inode),
	}
	subfs.inodes["."] = node

	prefix := dir + "/"
	for name, node := range fsys.inodes {
		if strings.HasPrefix(name, prefix) {
			subfs.inodes[strings.TrimPrefix(name, prefix)] = node
		}
	}
	return subfs, nil
}
