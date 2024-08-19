package xfile

import (
	"errors"
	"os"
	"path"
	"strings"
)

const (
	// WhiteoutPrefix is the prefix for whiteout file.
	// See https://github.com/opencontainers/image-spec/blob/main/layer.md#whiteouts
	WhiteoutPrefix = ".wh."
	// OpaqueWhiteout is the opaque whiteout file.
	// See https://github.com/opencontainers/image-spec/blob/main/layer.md#opaque-whiteout
	OpaqueWhiteout = WhiteoutPrefix + WhiteoutPrefix + ".opq"
	// PathSeparator is the string alias of os.PathSeparator
	PathSeparator = string(os.PathSeparator)
)

// Path represents a file path
type Path string

// Normalize returns the cleaned file path representation (trimmed of spaces and resolve relative notations)
func (p Path) Normalize() Path {
	// note: when normalizing we cannot trim trailing whitespace since it is valid for a path to have suffix whitespace
	var trimmed = string(p)
	if strings.Count(trimmed, " ") < len(trimmed) {
		trimmed = strings.TrimLeft(string(p), " ")
	}

	// remove trailing dir separators
	trimmed = strings.TrimRight(trimmed, PathSeparator)

	// special case for root "/"
	if trimmed == "" {
		return Path(PathSeparator)
	}
	return Path(path.Clean(trimmed))
}

// IsAbsolutePath returns true if the path is an absolute path.
func (p Path) IsAbsolutePath() bool {
	return strings.HasPrefix(string(p), PathSeparator)
}

// Basename of the path (i.e. filename)
func (p Path) Basename() string {
	return path.Base(string(p))
}

// IsDirWhiteout indicates if the path has a basename is a opaque whiteout (which means all parent directory contents should be ignored during squashing)
func (p Path) IsDirWhiteout() bool {
	return p.Basename() == OpaqueWhiteout
}

// IsWhiteout indicates if the file basename has a whiteout prefix (which means that the file should be removed during squashing)
func (p Path) IsWhiteout() bool {
	return strings.HasPrefix(p.Basename(), WhiteoutPrefix)
}

// IsFileWhiteout indicates if the file basename has a whiteout prefix, except a directory (which means that the file should be removed during squashing)
func (p Path) IsFileWhiteout() bool {
	return p.IsWhiteout() && !p.IsDirWhiteout()
}

// UnWhiteoutPath is a representation of the current path with no whiteout prefixes
func (p Path) UnWhiteoutPath() (Path, error) {
	basename := p.Basename()
	if strings.HasPrefix(basename, OpaqueWhiteout) {
		return p.ParentPath()
	}
	parent, err := p.ParentPath()
	if err != nil {
		return "", err
	}
	return Path(path.Join(string(parent), strings.TrimPrefix(basename, WhiteoutPrefix))), nil
}

// ParentPath returns a path object to the current files parent directory (or errors out if there is no parent)
func (p Path) ParentPath() (Path, error) {
	parent, child := path.Split(string(p))
	sanitized := Path(parent).Normalize()
	if sanitized == "/" {
		if child != "" {
			return "/", nil
		}
		return "", errors.New("no parent")
	}
	return sanitized, nil
}

// AllPaths returns all constituent paths of the current path + the current path itself (e.g. /home/wagoodman/file.txt -> /, /home, /home/wagoodman, /home/wagoodman/file.txt )
func (p Path) AllPaths() []Path {
	fullPaths := p.ConstituentPaths()
	if p != "/" {
		fullPaths = append(fullPaths, p)
	}
	return fullPaths
}

// ConstituentPaths returns all constituent paths for the current path (not including the current path itself) (e.g. /home/wagoodman/file.txt -> /, /home, /home/wagoodman )
func (p Path) ConstituentPaths() []Path {
	parents := strings.Split(strings.Trim(string(p), PathSeparator), PathSeparator)
	fullPaths := make([]Path, len(parents))
	for idx := range parents {
		cur := PathSeparator + strings.Join(parents[:idx], PathSeparator)
		fullPaths[idx] = Path(cur)
	}
	return fullPaths
}

// Paths is a list of paths implementing sort.Interface.
type Paths []Path

func (p Paths) Len() int           { return len(p) }
func (p Paths) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p Paths) Less(i, j int) bool { return string(p[i]) < string(p[j]) }

// PathStack is a stack of paths.
type PathStack []Path

// Size returns the length of the stack.
func (s *PathStack) Size() int {
	return len(*s)
}

// Pop returns the top path in the stack.
func (s *PathStack) Pop() Path {
	v := *s
	v, n := v[:len(v)-1], v[len(v)-1]
	*s = v
	return n
}

// Push adds a path to the stack.
func (s *PathStack) Push(n Path) {
	*s = append(*s, n)
}

// PathSet is a set of paths.
type PathSet map[Path]struct{}

// NewPathSet returns a new PathSet.
func NewPathSet() PathSet {
	return make(PathSet)
}

// Add adds a path to the set.
func (s PathSet) Add(i Path) {
	s[i] = struct{}{}
}

// Remove removes a path from the set.
func (s PathSet) Remove(i Path) {
	delete(s, i)
}

// Contains returns true if the set contains the path.
func (s PathSet) Contains(i Path) bool {
	_, ok := s[i]
	return ok
}
