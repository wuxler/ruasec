package homedir

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

// MustGet returns the home directory of the current user and omit
// panic when err returned by Get() is not nil.
func MustGet() string {
	home, err := Get()
	if err != nil {
		panic(err)
	}
	return home
}

// Get returns the home directory of the current user with the help of
// environment variables depending on the target operating system.
// Returned path should be used with "path/filepath" to form new paths.
//
// If linking statically with cgo enabled against glibc, ensure the
// osusergo build tag is used.
//
// If needing to do nss lookups, do not disable cgo or set osusergo.
func Get() (string, error) {
	var errs []error
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home, nil
	} else {
		errs = append(errs, err)
	}
	if u, err := user.Current(); err == nil && u != nil {
		return u.HomeDir, nil
	} else {
		errs = append(errs, err)
	}
	return "", fmt.Errorf("unable to determine home directory: %w", errors.Join(errs...))
}

// MustExpand expands the path to include the home directory if the
// path is prefixed with `~` and omit panic when err returned by
// Expand() is not nil.
func MustExpand(path string) string {
	expand, err := Expand(path)
	if err != nil {
		panic(err)
	}
	return expand
}

// Expand expands the path to include the home directory if the path
// is prefixed with `~`. If it isn't prefixed with `~`, the path is
// returned as-is.
func Expand(path string) (string, error) {
	if path == "" {
		return path, nil
	}

	if path[0] != '~' {
		return path, nil
	}

	if len(path) > 1 && path[1] != '/' && path[1] != '\\' {
		return "", errors.New("cannot expand user-specific home dir")
	}

	home, err := Get()
	if err != nil {
		return "", fmt.Errorf("cannot get user-specific home dir: %w", err)
	}

	return filepath.Join(home, path[1:]), nil
}
