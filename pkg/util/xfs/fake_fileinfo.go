package xfs

import (
	"io/fs"
	"path"
	"time"
)

var (
	_ fs.FileInfo = (*FakeFileInfo)(nil)
)

// NewFakeDirFileInfo creates a new *[FakeFileInfo] with mode set to fs.ModeDir.
func NewFakeDirFileInfo(name string) *FakeFileInfo {
	return NewFakeFileInfo(name).WithMode(fs.ModeDir | 0o644) //nolint:gomnd // defult permission mode mask
}

// NewFakeFileInfo creates a new *[FakeFileInfo].
func NewFakeFileInfo(name string) *FakeFileInfo {
	return &FakeFileInfo{name: path.Base(path.Clean(name))}
}

// FakeFileInfo is a fake file info implements [fs.FileInfo].
type FakeFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	sysStat any
}

// Name returns the base name of the file.
func (fi *FakeFileInfo) Name() string {
	return fi.name
}

// Size return the length in bytes of the file.
func (fi *FakeFileInfo) Size() int64 {
	return fi.size
}

// WithSize sets the size of the file.
func (fi *FakeFileInfo) WithSize(size int64) *FakeFileInfo {
	fi.size = size
	return fi
}

// Mode returns the file mode bits.
func (fi *FakeFileInfo) Mode() fs.FileMode {
	return fi.mode
}

// WithMode sets the file mode bits.
func (fi *FakeFileInfo) WithMode(mode fs.FileMode) *FakeFileInfo {
	fi.mode = mode
	return fi
}

// ModTime returns the modification time.
func (fi *FakeFileInfo) ModTime() time.Time {
	return fi.modTime
}

// WithModTime sets the modification time.
func (fi *FakeFileInfo) WithModTime(modTime time.Time) *FakeFileInfo {
	fi.modTime = modTime
	return fi
}

// IsDir returns a boolean indicating whether the file is a directory.
func (fi *FakeFileInfo) IsDir() bool {
	return fi.mode.IsDir()
}

// Sys returns the underlying data source (can return nil).
func (fi *FakeFileInfo) Sys() any {
	return fi.sysStat
}

// WithSysStat sets the underlying data source.
func (fi *FakeFileInfo) WithSysStat(stat any) *FakeFileInfo {
	fi.sysStat = stat
	return fi
}
