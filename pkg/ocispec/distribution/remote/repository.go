package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	stdurl "net/url"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cast"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec/authn"
	"github.com/wuxler/ruasec/pkg/ocispec/cas"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

// NewRepository creates a client for the remote repository.
// The name should contains the registry address if the target repository is not deployed
// at DockerHub.
func NewRepository(name string, opts ...Option) (distribution.Repository, error) {
	return NewRepositoryWithContext(context.Background(), name, opts...)
}

// NewRepositoryWithContext creates a client for the remote repository with the context.
// The name should contains the registry address if the target repository is not deployed
// at DockerHub.
func NewRepositoryWithContext(ctx context.Context, name string, opts ...Option) (distribution.Repository, error) {
	repoName, err := ocispecname.NewRepository(name)
	if err != nil {
		return nil, err
	}
	reg, err := NewRegistryWithContext(ctx, repoName.Domain().String(), opts...)
	if err != nil {
		return nil, err
	}
	return reg.Repository(ctx, repoName.Path())
}

type Repository struct {
	*Registry
	name ocispecname.Repository
}

// Named returns the name of the repository.
func (repo *Repository) Named() ocispecname.Repository {
	return repo.name
}

// Manifests returns a reference to this repository's manifest storage.
func (repo *Repository) Manifests() distribution.ManifestStore {
	return &manifestStore{repo}
}

// Tags returns a reference to this repository's tag storage.
func (repo *Repository) Tags() distribution.TagStore {
	return &tagStore{repo}
}

// Blobs returns a reference to this repository's blob storage.
func (repo *Repository) Blobs() distribution.BlobStore {
	return &blobStore{repo}
}

func (repo *Repository) builder() *distribution.RouteBuilder {
	return repo.Registry.builder().WithName(repo.Named().Path())
}

// StatManifest returns the descriptor for a given tag or digest.
// Only the MediaType, Digest and Size fields will be filled out in returned Descriptor.
func (repo *Repository) statManifest(ctx context.Context, tagOrDigest string) (imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor

	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo.Named().Path(), authn.ActionPull))
	endpoint := repo.builder().WithReference(tagOrDigest).Endpoint(distribution.RouteManifestsHead)

	request, err := endpoint.BuildRequest(ctx)
	if err != nil {
		return zero, err
	}
	request.Header.Set("Accept", manifestAcceptHeader())

	resp, err := repo.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return zero, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := distribution.HTTPSuccess(resp, endpoint.Descriptor().SuccessCodes...); err != nil {
		return zero, err
	}

	var dgst digest.Digest
	if parsed, err := digest.Parse(tagOrDigest); err == nil {
		dgst = parsed
	}

	desc, err := distribution.DescriptorFromResponse(resp, dgst)
	if err != nil {
		return zero, err
	}

	return desc, nil
}

// fetchManifest returns the contents of the manifest with the given tag or digest.
// The context also controls the lifetime of the returned DescribableReadCloser.
func (repo *Repository) fetchManifest(ctx context.Context, tagOrDigest string) (cas.ReadCloser, error) {
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo.Named().Path(), authn.ActionPull))
	endpoint := repo.builder().WithReference(tagOrDigest).Endpoint(distribution.RouteManifestsGet)

	request, err := endpoint.BuildRequest(ctx)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", manifestAcceptHeader())

	resp, err := repo.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return nil, err
	}
	if err := distribution.HTTPSuccess(resp, endpoint.Descriptor().SuccessCodes...); err != nil {
		return nil, err
	}

	var dgst digest.Digest
	if parsed, err := digest.Parse(tagOrDigest); err == nil {
		dgst = parsed
	}
	desc, err := distribution.DescriptorFromResponse(resp, dgst)
	if err != nil {
		return nil, err
	}

	return cas.NewReadCloser(resp.Body, desc), nil
}

// deleteManifest deletes the manifest with the given digest in the given repository.
func (repo *Repository) deleteManifest(ctx context.Context, dgst digest.Digest) error {
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo.Named().Path(), authn.ActionDelete))
	endpoint := repo.builder().WithReference(dgst.String()).Endpoint(distribution.RouteManifestsDelete)
	request, err := endpoint.BuildRequest(ctx)
	if err != nil {
		return err
	}
	resp, err := repo.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := distribution.HTTPSuccess(resp, endpoint.Descriptor().SuccessCodes...); err != nil {
		return err
	}
	return nil
}

// pushManifest pushes a manifest with the given media type and contents.
// If mediaType is not specified, "application/octet-stream" is used.
func (repo *Repository) pushManifest(ctx context.Context, target cas.Reader, tag string) error {
	// pushing usually requires both pull and push actions.
	// Reference: https://github.com/distribution/distribution/blob/v2.7.1/registry/handlers/app.go#L921-L930
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo.Named().Path(), authn.ActionPull, authn.ActionPush))

	ref := tag
	if ref == "" {
		ref = target.Descriptor().Digest.String()
	}
	content, err := io.ReadAll(target)
	if err != nil {
		return err
	}
	endpoint := repo.builder().
		WithReference(ref).
		WithBody(bytes.NewReader(content)).
		Endpoint(distribution.RouteManifestsPut)

	request, err := endpoint.BuildRequest(ctx)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", target.Descriptor().MediaType)
	resp, err := repo.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := distribution.HTTPSuccess(resp, endpoint.Descriptor().SuccessCodes...); err != nil {
		return err
	}
	return nil
}

type manifestStore struct {
	*Repository
}

// Stat returns the descriptor for the given reference.
func (s *manifestStore) Stat(ctx context.Context, reference string) (imgspecv1.Descriptor, error) {
	return s.Repository.statManifest(ctx, reference)
}

// Exists returns true if the described content exists.
func (s *manifestStore) Exists(ctx context.Context, target imgspecv1.Descriptor) (bool, error) {
	_, err := s.Stat(ctx, target.Digest.String())
	if err == nil {
		return true, nil
	}
	if errors.Is(err, errdefs.ErrNotFound) {
		return false, nil
	}
	return false, err
}

// Fetch fetches the content identified by the descriptor.
func (s *manifestStore) Fetch(ctx context.Context, target imgspecv1.Descriptor) (cas.ReadCloser, error) {
	return s.Repository.fetchManifest(ctx, target.Digest.String())
}

// Push pushes the content [Reader].
func (s *manifestStore) Push(ctx context.Context, target cas.Reader) error {
	return s.Repository.pushManifest(ctx, target, "")
}

// Delete removes the content identified by the descriptor.
func (s *manifestStore) Delete(ctx context.Context, target imgspecv1.Descriptor) error {
	return s.Repository.deleteManifest(ctx, target.Digest)
}

// FetchTagOrDigest fetches the content identified by the tag or digest.
func (s *manifestStore) FetchTagOrDigest(ctx context.Context, tagOrDigest string) (cas.ReadCloser, error) {
	return s.Repository.fetchManifest(ctx, tagOrDigest)
}

// StatTagOrDigest returns the descriptor for the given tag or digest.
func (s *manifestStore) StatTagOrDigest(ctx context.Context, tagOrDigest string) (imgspecv1.Descriptor, error) {
	return s.Repository.statManifest(ctx, tagOrDigest)
}

type tagStore struct {
	*Repository
}

// Stat retrieves the descriptor identified by the given tag.
func (s *tagStore) Stat(ctx context.Context, tag string) (imgspecv1.Descriptor, error) {
	return s.Manifests().StatTagOrDigest(ctx, tag)
}

// Tag tags a descriptor by the given tag.
func (s *tagStore) Tag(ctx context.Context, target cas.Reader, tag string) error {
	return s.Repository.pushManifest(ctx, target, tag)
}

// Untag removes the tag.
func (s *tagStore) Untag(ctx context.Context, tag string) error {
	desc, err := s.Stat(ctx, tag)
	if err != nil {
		return err
	}
	return s.Repository.deleteManifest(ctx, desc.Digest)
}

// List lists the tags.
func (s *tagStore) List(options ...distribution.ListOption) distribution.Iterator[string] {
	return &tagIterator{
		Repository: s.Repository,
		options:    distribution.MakeListOptions(options...),
		endpoint:   s.builder().Endpoint(distribution.RouteTagsList),
	}
}

type tagIterator struct {
	*Repository
	options  *distribution.ListOptions
	endpoint distribution.Endpoint

	// private attributes
	next *stdurl.URL
	done bool
}

// Next called for next page. If no more items to iterate, returns error with ErrIteratorDone.
func (it *tagIterator) Next(ctx context.Context) ([]string, error) {
	if it.done {
		return nil, distribution.ErrIteratorDone
	}
	if err := it.init(); err != nil {
		return nil, err
	}

	ctx = authn.WithScopes(ctx, authn.RepositoryScope(it.Named().Path(), authn.ActionPull))
	route := it.endpoint.Descriptor()
	request, err := http.NewRequestWithContext(ctx, route.Method, it.next.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := it.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := distribution.HTTPSuccess(resp, route.SuccessCodes...); err != nil {
		return nil, err
	}

	type tagsResponse struct {
		Name string   `json:"name"` // Name is the name of the repository
		Tags []string `json:"tags"`
	}

	parsed := tagsResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	next, err := distribution.GetNextPageURL(resp)
	if err != nil {
		if errors.Is(err, errdefs.ErrNotFound) {
			it.done = true
		} else {
			return nil, err
		}
	}
	it.next = next
	return parsed.Tags, nil
}

func (it *tagIterator) init() error {
	if it.next != nil {
		return nil
	}
	url, err := it.endpoint.BuildURL()
	if err != nil {
		return err
	}
	query := url.Query()
	if it.options.Offset != "" {
		query.Set("last", it.options.Offset)
	}
	if it.options.PageSize > 0 {
		query.Set("n", cast.ToString(it.options.PageSize))
	}
	url.RawQuery = query.Encode()
	it.next = url
	return nil
}

type blobStore struct {
	*Repository
}

// Stat returns the descriptor for the given reference.
func (s *blobStore) Stat(ctx context.Context, reference string) (imgspecv1.Descriptor, error) {
	panic("not implemented") // TODO: Implement
}

// Exists returns true if the described content exists.
func (s *blobStore) Exists(ctx context.Context, target imgspecv1.Descriptor) (bool, error) {
	panic("not implemented") // TODO: Implement
}

// Fetch fetches the content identified by the descriptor.
func (s *blobStore) Fetch(ctx context.Context, target imgspecv1.Descriptor) (cas.ReadCloser, error) {
	panic("not implemented") // TODO: Implement
}

// Push pushes the content [Reader].
func (s *blobStore) Push(ctx context.Context, content cas.Reader) error {
	panic("not implemented") // TODO: Implement
}

// Delete removes the content identified by the descriptor.
func (s *blobStore) Delete(ctx context.Context, target imgspecv1.Descriptor) error {
	panic("not implemented") // TODO: Implement
}
