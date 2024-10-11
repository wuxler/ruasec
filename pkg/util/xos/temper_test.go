package xos

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemper_String(t *testing.T) {
	root := "/path/to/root"
	patterns := []string{
		"a-*",
		"*-b",
		"c",
	}
	temp := NewTemper(root, patterns...)

	got := temp.String()
	want := root + "/" + filepath.Join(patterns...)
	assert.Equal(t, want, got)
}

func TestTemper_Path(t *testing.T) {
	tempDir := t.TempDir()
	root := NewTemper(tempDir, "pattern1-*", "pattern2-*")

	path, err := root.Path()
	require.NoError(t, err)
	assert.DirExists(t, path)

	rePattern := strings.ReplaceAll(filepath.ToSlash(tempDir), "/", `\/`)
	re := regexp.MustCompile(rePattern + `\/` + `pattern1-\d+` + `\/` + `pattern2-\d+`)
	got := re.MatchString(path)
	assert.True(t, got)
}

func TestTemper_NewChild(t *testing.T) {
	root := NewTemper("root")

	child1 := root.NewChild("child1-*")
	assert.Equal(t, "root/child1-*", child1.String())
	child2 := root.NewChild("child2-*")
	assert.Equal(t, "root/child2-*", child2.String())

	child11 := child1.NewChild("child1-1-*")
	assert.Equal(t, "root/child1-*/child1-1-*", child11.String())

	assert.Equal(t, "root", root.String())
}

func TestTemper_CreateTemp(t *testing.T) {
	tempDir := t.TempDir()
	root := NewTemper(tempDir)

	temp, err := root.CreateTemp("tempfile-*.txt")
	require.NoError(t, err)
	require.NoError(t, temp.Close())
	assert.FileExists(t, temp.Name())
}

func TestTemper_Cleanup(t *testing.T) {
	tempDir := t.TempDir()
	root := NewTemper(tempDir)

	rootTempFile, err := root.CreateTemp("root-temp-file-*")
	require.NoError(t, err)
	require.NoError(t, rootTempFile.Close())
	rootPath, err := root.Path()
	require.NoError(t, err)

	child1 := root.NewChild("child1-*")
	child1TempFile, err := child1.CreateTemp("child1-temp-file-*")
	require.NoError(t, err)
	require.NoError(t, child1TempFile.Close())
	child1Path, err := child1.Path()
	require.NoError(t, err)

	child2 := child1.NewChild("child2-*")
	child2TempFile, err := child2.CreateTemp("child2-temp-file-*")
	require.NoError(t, err)
	require.NoError(t, child2TempFile.Close())
	child2Path, err := child2.Path()
	require.NoError(t, err)

	child3 := child1.NewChild("child3-*")
	child3TempFile, err := child3.CreateTemp("child3-temp-file-*")
	require.NoError(t, err)
	require.NoError(t, child3TempFile.Close())
	child3Path, err := child3.Path()
	require.NoError(t, err)

	// setup filetree:
	// /root
	// ├── child1-*
	// │   ├── child1-temp-file-*
	// │   ├── child2-2679808191
	// │   │   └── child2-temp-file-*
	// │   └── child3-*
	// │       └── child3-temp-file-*
	// └── root-temp-file-*

	// cleanup child3
	require.NoError(t, child3.Cleanup())
	assert.NoDirExists(t, child3Path)
	assert.NoFileExists(t, child3TempFile.Name())

	assert.DirExists(t, child1Path)
	assert.FileExists(t, child1TempFile.Name())
	assert.DirExists(t, child2Path)
	assert.FileExists(t, child2TempFile.Name())
	assert.DirExists(t, rootPath)
	assert.FileExists(t, rootTempFile.Name())

	// cleanup root
	require.NoError(t, root.Cleanup())
	assert.NoDirExists(t, child1Path)
	assert.NoFileExists(t, child1TempFile.Name())
	assert.NoDirExists(t, child2Path)
	assert.NoFileExists(t, child2TempFile.Name())
	assert.NoDirExists(t, rootPath)
	assert.NoFileExists(t, rootTempFile.Name())
}
