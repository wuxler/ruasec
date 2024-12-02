package tarfs

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/util/xfs"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

func TestFS(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	tarfile := filepath.Join(tempDir, "test.tar")
	mktar(t, tarfile)
	want := []string{
		"tarfs.go",
		"tarfs_test.go",
		"entry.go",
		"testdata/foo",
		"testdata/bar",
	}
	t.Run("Sequence", func(t *testing.T) {
		rc, err := os.Open(tarfile)
		require.NoError(t, err)
		defer xio.CloseAndSkipError(rc)
		fsys, err := New(ctx, rc)
		require.NoError(t, err)
		assert.NoError(t, fstest.TestFS(fsys, want...))
	})

	t.Run("Parallel", func(t *testing.T) {
		rc, err := os.Open(tarfile)
		require.NoError(t, err)
		defer xio.CloseAndSkipError(rc)
		fsys, err := New(ctx, rc)
		require.NoError(t, err)

		const count = 8
		var wg sync.WaitGroup
		errs := make([]error, count)
		t.Logf("runninng %d goroutines", count)
		for i := 0; i < count; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = fstest.TestFS(fsys, want...)
			}()
		}
		wg.Wait()
		assert.NoError(t, errors.Join(errs...))
	})

	t.Run("Sub", func(t *testing.T) {
		rc, err := os.Open(tarfile)
		require.NoError(t, err)
		defer xio.CloseAndSkipError(rc)
		fsys, err := New(ctx, rc)
		require.NoError(t, err)

		testcases := []struct {
			input   string
			want    []string
			wantErr error
		}{
			{input: "testdata", want: []string{"foo", "bar"}},
			{input: "testdata/foo", wantErr: xfs.ErrIsNotDir},
			{input: "testdata/not-exists", wantErr: fs.ErrNotExist},
		}
		for _, tc := range testcases {
			t.Run(tc.input, func(t *testing.T) {
				sub, err := fs.Sub(fsys, tc.input)
				if tc.wantErr != nil {
					assert.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
				assert.NoError(t, fstest.TestFS(sub, tc.want...))
			})
		}
	})

	t.Run("ReadFile", func(t *testing.T) {
		rc, err := os.Open(tarfile)
		require.NoError(t, err)
		defer xio.CloseAndSkipError(rc)
		fsys, err := New(ctx, rc)
		require.NoError(t, err)

		testcases := []struct {
			input   string
			want    string
			wantErr error
		}{
			{input: "testdata/foo", want: "foo"},
			{input: "testdata/bar", want: "bar"},
			{input: "testdata/not-exist", wantErr: fs.ErrNotExist},
			{input: "testdata", wantErr: xfs.ErrIsDir},
		}
		for _, tc := range testcases {
			t.Run(tc.input, func(t *testing.T) {
				b, err := fs.ReadFile(fsys, tc.input)
				if tc.wantErr != nil {
					assert.ErrorIs(t, err, tc.wantErr)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tc.want, string(b))
			})
		}
	})
}

func mktar(t *testing.T, name string) {
	t.Helper()
	file, err := os.Create(name)
	require.NoError(t, err)
	defer xio.CloseAndSkipError(file)

	tw := tar.NewWriter(file)
	defer xio.CloseAndSkipError(tw)

	fsys := os.DirFS(".")
	err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if name == "." {
			return nil
		}
		if filepath.Ext(name) == ".tar" {
			return nil
		}
		if d.IsDir() {
			if name == ".git" {
				return fs.SkipDir
			}
		}
		t.Logf("adding %q", path)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		header.Name = path
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		current, err := fsys.Open(path)
		if err != nil {
			return err
		}
		defer xio.CloseAndSkipError(current)
		if _, err := io.Copy(tw, current); err != nil {
			return err
		}
		return nil
	})
	require.NoError(t, err)
}
