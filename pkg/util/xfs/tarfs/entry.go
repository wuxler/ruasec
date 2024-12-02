package tarfs

import (
	"io"
	"io/fs"
	"slices"

	"github.com/wuxler/ruasec/pkg/util/xfs"
)

var (
	_ fs.File        = (*entry)(nil)
	_ fs.ReadDirFile = (*entry)(nil)
)

type entry struct {
	*inode
	readdirOffset int
	reader        io.Reader
	closed        bool
}

func (ent *entry) check(op string, fileRequired bool) error {
	if ent.closed {
		return xfs.NewPathError(op, ent.Name(), fs.ErrClosed)
	}
	if fileRequired && ent.IsDir() {
		return xfs.NewPathError(op, ent.Name(), xfs.ErrIsDir)
	}
	return nil
}

func (ent *entry) Stat() (fs.FileInfo, error) {
	if err := ent.check("stat", false); err != nil {
		return nil, err
	}
	return ent.inode.Info()
}

func (ent *entry) Read(b []byte) (int, error) {
	if err := ent.check("read", true); err != nil {
		return 0, err
	}
	return ent.reader.Read(b)
}

func (ent *entry) Close() error {
	if err := ent.check("close", false); err != nil {
		return err
	}
	ent.closed = true
	return nil
}

func (ent *entry) ReadDir(n int) ([]fs.DirEntry, error) {
	if err := ent.check("readdir", false); err != nil {
		return nil, err
	}
	if !ent.IsDir() {
		return nil, xfs.NewPathError("readdir", ent.Name(), xfs.ErrIsNotDir)
	}

	if ent.readdirOffset >= len(ent.childrens) {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}

	last := ent.readdirOffset + n
	if n <= 0 || last > len(ent.childrens) {
		last = len(ent.childrens)
	}

	entries := slices.Clone(ent.childrens[ent.readdirOffset:last])
	ent.readdirOffset += len(entries)
	return entries, nil
}
