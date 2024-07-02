package name

import (
	"fmt"
	"strings"

	"github.com/opencontainers/go-digest"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/image/name/internal"
)

const (
	// nameTotalLengthMax is the maximum total number of characters in a repository name.
	nameTotalLengthMax = 255
)

type reference struct {
	repo   Repository
	tag    string
	digest digest.Digest
}

func (r reference) String() string {
	return r.repo.String() + ":" + r.tag + "@" + r.digest.String()
}

// Repository returns the name component as a Repository object.
func (r reference) Repository() Repository {
	return r.repo
}

// Tag returns the tag of the reference.
func (r reference) Tag() string {
	return r.tag
}

// Digest returns the digest of the reference.
func (r reference) Digest() digest.Digest {
	return r.digest
}

type taggedReference struct {
	repo Repository
	tag  string
}

func (r taggedReference) String() string {
	return r.repo.String() + ":" + r.tag
}

// Repository returns the name component as a Repository object.
func (r taggedReference) Repository() Repository {
	return r.repo
}

// Tag returns the tag of the reference.
func (r taggedReference) Tag() string {
	return r.tag
}

type digestedReference struct {
	repo   Repository
	digest digest.Digest
}

func (r digestedReference) String() string {
	return r.repo.String() + "@" + r.digest.String()
}

// Repository returns the name component as a Repository object.
func (r digestedReference) Repository() Repository {
	return r.repo
}

// Digest returns the digest of the reference.
func (r digestedReference) Digest() digest.Digest {
	return r.digest
}

func newReference(name string, opts options) (Reference, error) {
	r, err := parseReference(name, opts)
	if err != nil {
		return nil, fmt.Errorf("unable to parse reference %q: %w", name, err)
	}
	if err := ValidateReference(r); err != nil {
		return nil, fmt.Errorf("invalid reference %q: %w", name, err)
	}
	return r, nil
}

func parseReference(name string, opts options) (Reference, error) {
	var zero Reference
	scheme, name := splitAndTrimScheme(name)

	matches := internal.AnchoredReferenceRegexp.FindStringSubmatch(name)
	if matches == nil {
		if name == "" {
			return zero, errdefs.Newf(ErrBadName, "non-empty reference name is required")
		}
		if internal.AnchoredReferenceRegexp.FindStringSubmatch(strings.ToLower(name)) != nil {
			return nil, errdefs.Newf(ErrBadName, "reference name must be lowercase")
		}
		return nil, errdefs.Newf(ErrBadName, "invalid reference name")
	}
	if len(matches[1]) > nameTotalLengthMax {
		return nil, errdefs.Newf(ErrBadName, "reference name exceeds maximum length %d", nameTotalLengthMax)
	}

	remoteName := matches[1]
	if scheme != "" {
		remoteName = scheme + "://" + remoteName //nolint:goconst // skip constant required
	}
	repo, err := newRepository(remoteName, opts)
	if err != nil {
		return nil, err
	}

	tag := matches[2]

	var dgst digest.Digest
	if matches[3] != "" {
		dgst, err = digest.Parse(matches[3])
		if err != nil {
			return nil, errdefs.Newf(ErrBadName, "invalid digest: %w", err)
		}
	}

	if tag == "" && dgst == "" {
		tag = opts.defaultTag
	}

	if tag != "" {
		if dgst != "" {
			return reference{repo: repo, tag: tag, digest: dgst}, nil
		}
		return taggedReference{repo: repo, tag: tag}, nil
	}
	if dgst != "" {
		return digestedReference{repo: repo, digest: dgst}, nil
	}

	return nil, errdefs.Newf(ErrBadName, "both tag or digest not specified: missing reference")
}
