package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	stdurl "net/url"
	"strings"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/samber/lo"
	"github.com/spf13/cast"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/ocispec/authn"
	"github.com/wuxler/ruasec/pkg/ocispec/cas"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
	"github.com/wuxler/ruasec/pkg/ocispec/iter"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xhttp"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

var (
	_ distribution.Spec = (*Registry)(nil)
)

// Registry provides access to a remote registry.
type Registry struct {
	name   ocispecname.Registry
	client *Client
}

// Name returns the name of the registry.
func (spec *Registry) Name() ocispecname.Registry {
	return spec.name
}

// Spec returns the distribution-spec interface.
func (spec *Registry) Spec() distribution.Spec {
	return spec
}

// Ping checks registry is accessible.
func (spec *Registry) Ping(ctx context.Context) error {
	_, err := spec.GetVersion(ctx)
	return err
}

// RepositoryE returns the [Repository] by the given path which is the repository name.
//
// NOTE: Invalid "path" will cause panic.
func (spec *Registry) Repository(path string) *Repository {
	repo, err := spec.RepositoryE(path)
	if err != nil {
		panic(err)
	}
	return repo
}

// Repository returns the [Repository] by the given path which is the repository name.
func (spec *Registry) RepositoryE(path string) (*Repository, error) {
	name, err := ocispecname.WithPath(spec.Name(), path)
	if err != nil {
		return nil, err
	}
	repo := &Repository{
		registry: spec,
		name:     name,
	}
	return repo, nil
}

func (spec *Registry) endpoint(path string) string {
	path = strings.TrimPrefix(path, "/")
	return fmt.Sprintf("%s://%s/%s", spec.name.Scheme(), spec.name.Hostname(), path)
}

// GetVersion checks the registry accessible and returns the properties of the registry.
func (spec *Registry) GetVersion(ctx context.Context) (string, error) {
	url := spec.endpoint("/v2/")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return "", err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := xhttp.Success(resp); err != nil {
		return "", err
	}
	return resp.Header.Get("Docker-Distribution-API-Version"), nil
}

// StatManifest returns the descriptor of the manifest with the given reference.
func (spec *Registry) StatManifest(ctx context.Context, repo string, reference string) (imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor

	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/manifests/%s", repo, reference))
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, url, http.NoBody)
	if err != nil {
		return zero, err
	}
	request.Header.Set("Accept", ManifestAcceptHeader())

	resp, err := spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return zero, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := xhttp.Success(resp); err != nil {
		return zero, err
	}

	var dgst digest.Digest
	if parsed, err := digest.Parse(reference); err == nil {
		dgst = parsed
	}
	desc, err := makeDescriptorFromResponse(resp, dgst)
	if err != nil {
		return zero, err
	}

	return desc, nil
}

// GetManifest returns the content of the manifest with the given reference.
func (spec *Registry) GetManifest(ctx context.Context, repo string, reference string) (cas.ReadCloser, error) {
	resp, err := spec.doGetManifestRequest(ctx, repo, reference) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return nil, err
	}
	if err := xhttp.Success(resp); err != nil {
		xio.CloseAndSkipError(resp.Body)
		return nil, err
	}

	var dgst digest.Digest
	if parsed, err := digest.Parse(reference); err == nil {
		dgst = parsed
	}
	desc, err := makeDescriptorFromResponse(resp, dgst)
	if err != nil {
		xio.CloseAndSkipError(resp.Body)
		return nil, err
	}

	return cas.NewReadCloser(resp.Body, desc), nil
}

func (spec *Registry) doGetManifestRequest(ctx context.Context, repo string, reference string) (*http.Response, error) {
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/manifests/%s", repo, reference))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", ManifestAcceptHeader())

	return spec.client.Do(request)
}

// StatBlob returns the descriptor of the blob with the given digest.
func (spec *Registry) StatBlob(ctx context.Context, repo string, dgst digest.Digest) (imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor

	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/blobs/%s", repo, dgst))
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, url, http.NoBody)
	if err != nil {
		return zero, err
	}

	resp, err := spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return zero, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := xhttp.Success(resp); err != nil {
		return zero, err
	}

	return makeDescriptorFromResponse(resp, dgst)
}

// GetBlob returns the content of the blob with the given digest.
func (spec *Registry) GetBlob(ctx context.Context, repo string, dgst digest.Digest) (cas.ReadCloser, error) {
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/blobs/%s", repo, dgst))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return nil, err
	}
	if err := xhttp.Success(resp); err != nil {
		xio.CloseAndSkipError(resp.Body)
		return nil, err
	}

	var desc imgspecv1.Descriptor
	if resp.ContentLength == -1 {
		desc, err = spec.StatBlob(ctx, repo, dgst)
	} else {
		desc, err = makeDescriptorFromResponse(resp, dgst)
	}
	if err != nil {
		xio.CloseAndSkipError(resp.Body)
		return nil, err
	}
	rc := resp.Body

	// Check server range request capability.
	// Docker spec allows range header form of "Range: bytes=<start>-<end>".
	// However, the remote server may still not RFC 7233 compliant.
	// Reference: https://docs.docker.com/registry/spec/api/#blob
	if rangeUnit := resp.Header.Get("Accept-Ranges"); rangeUnit == "bytes" {
		rc = xhttp.NewReadSeekCloser(spec.client, request, resp.Body, desc.Size)
	}

	return cas.NewReadCloser(rc, desc), nil
}

// PushManifest pushes a manifest with the given descriptor and tags.
func (spec *Registry) PushManifest(ctx context.Context, repo string, r cas.Reader, tags ...string) error {
	content, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	desc := r.Descriptor()
	refs := []string{}
	if desc.Digest != "" {
		refs = append(refs, desc.Digest.String())
	}
	refs = append(refs, tags...)

	for _, ref := range refs {
		if err := spec.pushManifest(ctx, repo, desc, content, ref); err != nil {
			return err
		}
	}
	return nil
}

func (spec *Registry) pushManifest(ctx context.Context, repo string, desc imgspecv1.Descriptor, content []byte, ref string) error {
	// pushing usually requires both pull and push actions.
	// Reference: https://github.com/distribution/distribution/blob/v2.7.1/registry/handlers/app.go#L921-L930
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull, authn.ActionPush))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/manifests/%s", repo, ref))
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(content))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", desc.MediaType)
	resp, err := spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	// allowed with code 201
	return xhttp.Success(resp, http.StatusCreated)
}

// PushBlob pushes a blob monolithically to the given repository, reading the descriptor
// and content from "getter".
//
// Push is done by conventional 2-step monolithic upload instead of a single
// `POST` request for better overall performance. It also allows early fail on
// authentication errors.
func (spec *Registry) PushBlob(ctx context.Context, repo string, getter cas.ReadCloserGetter) error {
	// start to upload with "POST"
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull, authn.ActionPush))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/blobs/uploads/", repo))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)

	if err := xhttp.Success(resp, http.StatusAccepted); err != nil {
		return err
	}
	// complete the upload with "PUT"
	return spec.completePushAfterPost(ctx, request, resp, getter)
}

// PushBlobChunked starts to push a blob to the given repository.
// The returned [BlobWriteCloser] can be used to stream the upload and resume on
// temporary errors.
//
// The chunkSize parameter provides a hint for the chunk size to use when writing
// to the registry. If it's zero, a suitable default will be chosen. It might be
// larger if the underlying registry requires that.
//
// The context remains active as long as the BlobWriteCloser is around: if it's
// canceled, it should cause any blocked BlobWriteCloser operations to terminate.
func (spec *Registry) PushBlobChunked(ctx context.Context, repo string, chunkSize int64) (distribution.BlobWriteCloser, error) {
	if chunkSize <= 0 {
		chunkSize = distribution.DefaultChunkSize
	}
	// start to upload with "POST"
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull, authn.ActionPush))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/blobs/uploads/", repo))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := xhttp.Success(resp, http.StatusAccepted); err != nil {
		return nil, err
	}

	location, err := resp.Location()
	if err != nil {
		return nil, xhttp.MakeResponseError(resp, fmt.Errorf("bad Location in response header: %w", err))
	}
	chunkSize = chunkSizeFromResponse(resp, chunkSize)
	return &blobWriter{
		ctx:       ctx,
		spec:      spec,
		chunkSize: chunkSize,
		chunk:     make([]byte, 0, chunkSize),
		location:  location,
	}, nil
}

// PushBlobChunkedResume resumes a previous push of a blob started with PushBlobChunked.
// The id should be the value returned from [BlobWriteCloser.ID] from the previous push.
// and the offset should be the value returned from [BlobWriteCloser.Size].
//
// The offset and chunkSize should similarly be obtained from the previous [BlobWriterCloser]
// via the [BlobWriteCloser.Size] and [BlobWriteCloser.ChunkSize] methods.
// Alternatively, set offset to -1 to continue where the last write left off,
// and to only use chunkSize as a hint like in PushBlobChunked.
//
// The context remains active as long as the BlobWriteCloser is around: if it's
// canceled, it should cause any blocked BlobWriteCloser operations to terminate.
func (spec *Registry) PushBlobChunkedResume(ctx context.Context, repo string, chunkSize int64, id string, offset int64) (distribution.BlobWriteCloser, error) {
	if id == "" {
		return nil, errdefs.Newf(errdefs.ErrInvalidParameter, "id is required to resume a chunked upload")
	}
	if chunkSize <= 0 {
		chunkSize = distribution.DefaultChunkSize
	}
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull, authn.ActionPush, authn.ActionDelete))

	if offset < -1 {
		return nil, errdefs.Newf(errdefs.ErrInvalidParameter, "invalid offset: must be -1 or non-negative but got %d", offset)
	}

	url := spec.endpoint(fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, id))
	location, err := stdurl.Parse(url)
	if err != nil {
		return nil, err
	}

	if offset == -1 {
		resp, err := spec.doGetUploadStatusRequest(ctx, repo, id) //nolint:bodyclose // closed by xio.CloseAndSkipError
		if err != nil {
			return nil, fmt.Errorf("cannot recover chunk offset: %w", err)
		}
		defer xio.CloseAndSkipError(resp.Body)
		if err := xhttp.Success(resp, http.StatusNoContent); err != nil {
			return nil, err
		}
		// parse Location header
		location, err = resp.Location()
		if err != nil {
			return nil, fmt.Errorf("bad Location in response header: %w", err)
		}
		// parse Range header to fix offset
		rangeHeader := resp.Header.Get("Range")
		start, end, ok := xhttp.ParseRange(rangeHeader)
		if !ok {
			return nil, fmt.Errorf("invalid range %q in response header", rangeHeader)
		}
		if start != 0 {
			return nil, fmt.Errorf("range %q does not start with 0", rangeHeader)
		}
		chunkSize = chunkSizeFromResponse(resp, chunkSize)
		offset = end
	}

	return &blobWriter{
		ctx:       ctx,
		spec:      spec,
		chunkSize: chunkSize,
		size:      offset,
		flushed:   offset,
		location:  location,
	}, nil
}

func (spec *Registry) doGetUploadStatusRequest(ctx context.Context, repo string, id string) (*http.Response, error) {
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull, authn.ActionPush))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, id))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	return spec.client.Do(request)
}

// MountBlob makes a blob with the given digest that's in "from" repository available
// in "repo" repository and returns mounted successfully or not.
//
// As [distribution-spec] specified:
//
// "Alternatively, if a registry does not support cross-repository mounting or is unable
// to mount the requested blob, it SHOULD return a 202. This indicates that the upload
// session has begun and that the client MAY proceed with the upload."
//
// So the returns composites as follow:
//   - "true, nil" means mount succeed.
//   - "false, nil" means mount is unsupported.
//   - "false, err" means mount failed with unexpected error.
//
// [distribution-spec]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#mounting-a-blob-from-another-repository
func (spec *Registry) MountBlob(ctx context.Context, repo string, from string, dgst digest.Digest) (bool, error) {
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull, authn.ActionPush))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/blobs/uploads/?mount=%s&from=%s", repo, dgst, from))
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, url, http.NoBody)
	if err != nil {
		return false, err
	}
	resp, err := spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return false, err
	}
	defer xio.CloseAndSkipError(resp.Body)

	if err := xhttp.Success(resp, http.StatusCreated, http.StatusAccepted); err != nil {
		return false, err
	}

	if resp.StatusCode == http.StatusAccepted {
		werr := fmt.Errorf("unable to mount: %w", errdefs.ErrUnsupported)
		werr = xhttp.MakeResponseError(resp, werr)
		getter := func(ctx context.Context) (cas.ReadCloser, error) {
			return spec.GetBlob(ctx, from, dgst)
		}
		if err := spec.completePushAfterPost(ctx, request, resp, getter); err != nil {
			err = fmt.Errorf("fallback to pull and push blob content failed: %w", err)
			return false, errors.Join(werr, err)
		}
		return true, nil
	}

	// "201 Created" here means mount supported and succeed
	return true, nil
}

// completePushAfterPost implements step 2 of the push protocol.
// This can be invoked either by "Push" or by "Mount" when the receiving repository
// does not implement the mount endpoint.
func (spec *Registry) completePushAfterPost(ctx context.Context, postRequest *http.Request, postResp *http.Response, getter cas.ReadCloserGetter) error {
	// monolithic upload
	location, err := postResp.Location()
	if err != nil {
		return err
	}
	// Workaround solution for https://github.com/oras-project/oras-go/issues/177
	// For some registries, if the port 443 is explicitly set to the hostname
	// like registry.wabbit-networks.io:443/myrepo, blob push will fail since
	// the hostname of the Location header in the response is set to
	// registry.wabbit-networks.io instead of registry.wabbit-networks.io:443.
	//
	// If location port 443 is missing, add it back.
	expectHostname := postRequest.URL.Hostname()
	expectPort := postRequest.URL.Port()
	locationHostname := location.Hostname()
	locationPort := location.Port()
	if expectPort == "443" && locationHostname == expectHostname && locationPort == "" {
		location.Host = locationHostname + ":" + expectPort
	}
	url := location.String()

	rc, err := getter(ctx)
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(rc)
	expectDesc := rc.Descriptor()

	request, err := http.NewRequestWithContext(ctx, http.MethodPut, url, rc)
	if err != nil {
		return err
	}
	// set GetBody and ContentLength so that the request in client.Do() can be rewindable
	request.GetBody = func() (io.ReadCloser, error) {
		return getter(ctx)
	}
	request.ContentLength = expectDesc.Size
	// the expected media type is ignored as in the spec doc.
	request.Header.Set("Content-Type", ocispec.DefaultMediaType)
	query := request.URL.Query()
	query.Set("digest", expectDesc.Digest.String())
	request.URL.RawQuery = query.Encode()

	// reuse credential from previous POST request
	if auth := postResp.Request.Header.Get("Authorization"); auth != "" {
		request.Header.Set("Authorization", auth)
	}

	resp, err := spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)

	return xhttp.Success(resp, http.StatusCreated)
}

// DeleteManifest deletes the manifest with the given digest in the given repository.
func (spec *Registry) DeleteManifest(ctx context.Context, repo string, reference string) error {
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionDelete))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/manifests/%s", repo, reference))
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, http.NoBody)
	if err != nil {
		return err
	}

	resp, err := spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	// allowed with code 202
	return xhttp.Success(resp, http.StatusAccepted)
}

// DeleteBlob deletes the blob with the given digest in the given repository.
func (spec *Registry) DeleteBlob(ctx context.Context, repo string, dgst digest.Digest) error {
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionDelete))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/blobs/%s", repo, dgst))
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, http.NoBody)
	if err != nil {
		return err
	}

	resp, err := spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	// allowed with code 202
	return xhttp.Success(resp, http.StatusAccepted)
}

// ListRepositories returns an iterator that can be used to iterate
// over all the repositories in the registry in order.
func (spec *Registry) ListRepositories(opts ...distribution.ListOption) iter.Iterator[string] {
	options := distribution.MakeListOptions(opts...)
	return &repoIterator{
		spec:    spec,
		options: options,
	}
}

// ListTags returns an iterator that can be used to iterate over all
// the tags in the given repository in order.
func (spec *Registry) ListTags(repo string, opts ...distribution.ListOption) iter.Iterator[string] {
	options := distribution.MakeListOptions(opts...)
	return &tagIterator{
		spec:    spec,
		options: options,
		repo:    repo,
	}
}

// Referrers returns an iterator that can be used to iterate over all
// the manifests that have the given digest as their Subject.
//
// If "artifactType" is specified, the results will be restricted to
// only manifests with that type.
func (spec *Registry) ListReferrers(ctx context.Context, repo string, dgst digest.Digest, artifactType string) ([]imgspecv1.Descriptor, error) {
	return spec.GetReferrers(ctx, repo, dgst, artifactType)
}

// GetReferrers returns descriptors of referrers with the given "dgst" and
// "artifactType" used to filter artifacts.
//
// If the [Referrers API] returns a 404, the client MUST fallback to pulling
// the [Referrers Tag Schema]. The response SHOULD be an image index with the
// same content that would be expected from the [Referrers API]. If the response
// to the [Referrers API] is a 404, and the [Referrers Tag Schema] does not
// return a valid image index, the client SHOULD assume there are no referrers
// to the manifest.
//
// [Referrers API]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers
// [Referrers Tag Schema]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#referrers-tag-schema
func (spec *Registry) GetReferrers(ctx context.Context, repo string, dgst digest.Digest, artifactType string) ([]imgspecv1.Descriptor, error) {
	resp, err := spec.doGetReferrersRequest(ctx, repo, dgst, artifactType) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(resp.Body)

	err = xhttp.Success(resp, http.StatusNotFound)
	if err == nil {
		return spec.extractReferrersDescriptors(resp, artifactType)
	}

	// fallback to pulling referrers tag schema manifest on 404
	tag := fmt.Sprintf("%s-%s", dgst.Algorithm(), dgst.Encoded())
	//nolint:bodyclose // closed by xio.CloseAndSkipError
	fallbackResp, fallbackErr := spec.doGetManifestRequest(ctx, repo, tag)
	if fallbackErr != nil {
		return nil, errors.Join(err, fallbackErr)
	}
	defer xio.CloseAndSkipError(fallbackResp.Body)

	fallbackErr = xhttp.Success(resp)
	if fallbackErr == nil {
		return spec.extractReferrersDescriptors(resp, artifactType)
	}
	return nil, errors.Join(err, fallbackErr)
}

func (spec *Registry) extractReferrersDescriptors(resp *http.Response, artifactType string) ([]imgspecv1.Descriptor, error) {
	// parse response body
	parsed := &imgspecv1.Index{}
	if err := json.NewDecoder(resp.Body).Decode(parsed); err != nil {
		return nil, err
	}

	// validate media type
	if parsed.MediaType != ocispec.MediaTypeImageIndex {
		return nil, fmt.Errorf("mediaType expected to %q but got %q", ocispec.MediaTypeImageIndex, parsed.MediaType)
	}

	// filter by artifact type when registry not support filtering
	// FIXME(wulxer): Does artifact type filter support multiple applied ?
	descs := parsed.Manifests
	applied := resp.Header.Get("OCI-Filters-Applied")
	if applied == "" && artifactType != "" {
		descs = lo.Filter(descs, func(item imgspecv1.Descriptor, idx int) bool {
			return item.ArtifactType == artifactType
		})
	}
	return descs, nil
}

// doGetReferrersRequest fetches descriptors of the referrers with "GET /v2/<name>/referrers/<digest>"
// api endpoint.
func (spec *Registry) doGetReferrersRequest(ctx context.Context, repo string, dgst digest.Digest, artifactType string) (*http.Response, error) {
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	url := spec.endpoint(fmt.Sprintf("/v2/%s/referrers/%s", repo, dgst))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", ocispec.MediaTypeImageIndex)
	query := request.URL.Query()
	if artifactType != "" {
		query.Set("artifactType", artifactType)
	}
	request.URL.RawQuery = query.Encode()

	return spec.client.Do(request)
}

type repoIterator struct {
	spec    *Registry
	options *distribution.ListOptions

	// runtime arrtributes
	next *stdurl.URL
	done bool
}

// Next called for next page. If no more items to iterate, returns error with ErrIteratorDone.
func (it *repoIterator) Next(ctx context.Context) ([]string, error) {
	if it.done {
		return nil, iter.ErrIteratorDone
	}
	if err := it.init(); err != nil {
		return nil, err
	}
	ctx = authn.WithScopes(ctx, authn.DefaultRegistryCatalogScope)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, it.next.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := it.spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := xhttp.Success(resp); err != nil {
		return nil, err
	}

	type Response struct {
		Repositories []string `json:"repositories"`
	}

	parsed := Response{}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	next, err := getNextPageURL(resp)
	if err != nil {
		if errors.Is(err, errdefs.ErrNotFound) {
			it.done = true
		} else {
			return nil, err
		}
	}
	it.next = next

	return parsed.Repositories, nil
}

func (it *repoIterator) init() error {
	if it.next != nil {
		return nil
	}
	url, err := stdurl.Parse(it.spec.endpoint("/v2/_catalog"))
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

type tagIterator struct {
	spec    *Registry
	options *distribution.ListOptions
	repo    string

	// runtime arrtributes
	next *stdurl.URL
	done bool
}

// Next called for next page. If no more items to iterate, returns error with ErrIteratorDone.
func (it *tagIterator) Next(ctx context.Context) ([]string, error) {
	if it.done {
		return nil, iter.ErrIteratorDone
	}
	if err := it.init(); err != nil {
		return nil, err
	}
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(it.repo, authn.ActionPull))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, it.next.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := it.spec.client.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := xhttp.Success(resp); err != nil {
		return nil, err
	}

	type Response struct {
		Name string   `json:"name"` // Name is the name of the repository
		Tags []string `json:"tags"`
	}

	parsed := Response{}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	next, err := getNextPageURL(resp)
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
	url, err := stdurl.Parse(it.spec.endpoint(fmt.Sprintf("/v2/%s/tags/list", it.repo)))
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
