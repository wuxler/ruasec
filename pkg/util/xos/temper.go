package xos

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Temper is a file system temper interface, provides the operations to
// handle the temporary file and directory.
type Temper interface {
	fmt.Stringer

	// Path returns the root path of the temper, joining patterns with the
	// last "*" replaced by a random string for each pattern.
	Path() (string, error)

	// NewChild returns a new child temper with the given pattern.
	//
	// NOTE: The pattern should not contain the path separator like "/".
	// Otherwise, it will be replaced with "_".
	NewChild(pattern string) Temper

	// CreateTemp creates a new temporary file in the temper path.
	//
	// NOTE: The pattern should not contain the path separator like "/".
	// Otherwise, it will be replaced with "_".
	CreateTemp(pattern string) (*os.File, error)

	// Cleanup removes all files and directories under the temper path,
	// including the root path.
	Cleanup() error
}

// NewTemper creates a new temper with the given root path and patterns.
// If the root path is empty, it will use the system temporary directory.
//
// NOTE: The pattern should not contain the path separator like "/".
// Otherwise, it will be replaced with "_".
func NewTemper(root string, patterns ...string) Temper {
	return newTemper(root, patterns...)
}

func newTemper(root string, patterns ...string) *temper {
	if root == "" {
		root = os.TempDir()
	}
	t := &temper{root: root}
	for _, p := range patterns {
		p = santizedPattern(p)
		t = t.newChild(p)
	}
	return t
}

type temper struct {
	root    string
	pattern string

	location string
	parent   *temper
	children []*temper
	files    []string
	patterns []string
}

func (t *temper) hasParent() bool {
	return t.parent != nil
}

func (t *temper) allPatterns() []string {
	if len(t.patterns) > 0 {
		return t.patterns
	}

	patterns := []string{}
	cur := t
	for cur.hasParent() {
		patterns = append(patterns, cur.pattern)
		cur = cur.parent
	}
	// root node has no pattern
	slices.Reverse(patterns)
	t.patterns = patterns
	return t.patterns
}

// String returns the path with raw patterns joined.
func (t *temper) String() string {
	elems := append([]string{t.root}, t.allPatterns()...)
	return filepath.Join(elems...)
}

// Path returns the root path of the temper, joining patterns with the
// last "*" replaced by a random string for each pattern. It will lazyly
// create the path if it doesn't exist.
func (t *temper) Path() (string, error) {
	if t.location != "" {
		return t.location, nil
	}

	if !t.hasParent() {
		// current node is root
		t.location = t.root
		if err := os.MkdirAll(t.location, 0o750); err != nil {
			return "", err
		}
		return t.location, nil
	}

	parentPath, err := t.parent.Path()
	if err != nil {
		return "", err
	}
	tempDir, err := os.MkdirTemp(parentPath, t.pattern)
	if err != nil {
		return "", err
	}
	t.location = tempDir
	return t.location, nil
}

// NewChild returns a new child temper with the given pattern.
//
// NOTE: The pattern should not contain the path separator like "/".
// Otherwise, it will be replaced with "_".
func (t *temper) NewChild(pattern string) Temper {
	return t.newChild(pattern)
}

func (t *temper) newChild(pattern string) *temper {
	pattern = santizedPattern(pattern)
	patterns := slices.Clone(t.allPatterns())
	patterns = append(patterns, pattern)
	child := &temper{
		root:     t.root,
		pattern:  pattern,
		parent:   t,
		patterns: patterns,
	}
	t.children = append(t.children, child)
	return child
}

// CreateTemp creates a new temporary file in the temper path.
//
// NOTE: The pattern should not contain the path separator like "/".
// Otherwise, it will be replaced with "_".
func (t *temper) CreateTemp(pattern string) (*os.File, error) {
	pattern = santizedPattern(pattern)
	dir, err := t.Path()
	if err != nil {
		return nil, err
	}
	fd, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	t.files = append(t.files, fd.Name())
	return fd, nil
}

// Cleanup removes all files and directories under the temper path,
// including the root path.
func (t *temper) Cleanup() error {
	var errs []error
	for _, child := range t.children {
		if err := child.Cleanup(); err != nil {
			errs = append(errs, err)
		}
	}
	if t.location != "" {
		if err := os.RemoveAll(t.location); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// santizedPattern replaces all path separators with "_".
func santizedPattern(pattern string) string {
	return strings.ReplaceAll(pattern, string(os.PathSeparator), "_")
}
