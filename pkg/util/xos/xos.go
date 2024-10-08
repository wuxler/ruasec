package xos

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/wuxler/ruasec/pkg/util/xio"
)

// IsEmptyDir checks if a directory is empty.
// If the directory does not exist, it returns false.
// If the directory existed but does not contains any file, it returns true.
func IsEmptyDir(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer xio.CloseAndSkipError(f)

	if _, err = f.Readdirnames(1); errors.Is(err, io.EOF) {
		return true
	}
	return false
}

// Create is a wrapper for os.Create. It will automatically make the parent directory
// with "0o700" permission mode if it does not exist.
func Create(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return os.Create(path)
}

// Exists checks if a file or directory exists.
// If the file or directory does not exist, it returns false and nil error.
// If the file or directory is not accessible, it returns false and error.
func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}
