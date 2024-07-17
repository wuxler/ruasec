package distribution

import (
	"context"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/ocispec/cas"
	"github.com/wuxler/ruasec/pkg/ocispec/iter"
)

// TagStore is a storage interface for tags resource.
type TagStore interface {
	// Stat retrieves the descriptor identified by the given tag.
	Stat(ctx context.Context, tag string) (imgspecv1.Descriptor, error)
	// Tag tags the target by the given tag.
	Tag(ctx context.Context, target cas.Reader, tag string) error
	// Untag removes the tag.
	Untag(ctx context.Context, tag string) error
	// List lists the tags.
	List(options ...ListOption) iter.Iterator[string]
}

// NewTagStore returns a [TagStore] with the given distribution Spec
// and repository path formatted as "library/alpine".
func NewTagStore(spec Spec, repo string) TagStore {
	return &tagStore{spec: spec, repo: repo}
}

type tagStore struct {
	spec Spec
	repo string
}

// Stat retrieves the descriptor identified by the given tag.
func (s *tagStore) Stat(ctx context.Context, tag string) (imgspecv1.Descriptor, error) {
	return s.spec.StatManifest(ctx, s.repo, tag)
}

// Tag tags the target by the given tag.
func (s *tagStore) Tag(ctx context.Context, target cas.Reader, tag string) error {
	return s.spec.PushManifest(ctx, s.repo, target, tag)
}

// Untag removes the tag.
func (s *tagStore) Untag(ctx context.Context, tag string) error {
	return s.spec.DeleteManifest(ctx, s.repo, tag)
}

// List lists the tags.
func (s *tagStore) List(opts ...ListOption) iter.Iterator[string] {
	return s.spec.ListTags(s.repo, opts...)
}
