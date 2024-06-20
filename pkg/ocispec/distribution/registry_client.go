package distribution

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image/manifest"
	"github.com/wuxler/ruasec/pkg/image/name"
	"github.com/wuxler/ruasec/pkg/ocispec/authn"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

const (
	dockerContentDigestHeader = "Docker-Content-Digest"
)

var (
	defaultRequestedManifestMediaTypes = []string{
		manifest.MediaTypeDockerV2S2Manifest,
		manifest.MediaTypeDockerV2S2ManifestList,
		manifest.MediaTypeImageManifest,
		manifest.MediaTypeImageIndex,
		manifest.MediaTypeDockerV2S1Manifest,
		manifest.MediaTypeDockerV2S1SignedManifest,
	}
)

type RegistryClient struct {
	HTTPClient *Client
	registry   name.Registry
}

func (c *RegistryClient) builder() *routeBuilder {
	b := &routeBuilder{}
	return b.WithBaseURL(fmt.Sprintf("%s://%s", c.registry.Scheme(), c.registry.Hostname()))
}

// Ping checks if the storage is reachable.
func (c *RegistryClient) Ping(ctx context.Context) error {
	route := RoutePing
	request, err := c.builder().BuildRequest(ctx, route)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	return HTTPSuccess(resp, route.SuccessCodes...)
}

// GetManifest returns the contents of the manifest with the given tag or digest.
// The context also controls the lifetime of the returned DescribableReadCloser.
func (c *RegistryClient) GetManifest(ctx context.Context, repo string, tagOrDigest string) (DescribableReadCloser, error) {
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	route := RouteManifestsGet
	request, err := c.builder().WithName(repo).WithReference(tagOrDigest).BuildRequest(ctx, route)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", manifestAcceptHeader())
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // resp.Body is returned as a wrap
	if err != nil {
		return nil, err
	}
	if err := HTTPSuccess(resp, route.SuccessCodes...); err != nil {
		return nil, err
	}
	var dgst digest.Digest
	if parsed, err := digest.Parse(tagOrDigest); err == nil {
		dgst = parsed
	}
	desc, err := descriptorFromResponse(resp, dgst)
	if err != nil {
		return nil, err
	}
	return NewDescribableReadCloser(resp.Body, desc), nil
}

func (c *RegistryClient) headManifest(ctx context.Context, repo string, tagOrDigest string) (v1.Descriptor, error) {
	var zero v1.Descriptor
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	route := RouteManifestsHead
	request, err := c.builder().WithName(repo).WithReference(tagOrDigest).BuildRequest(ctx, route)
	if err != nil {
		return zero, err
	}
	request.Header.Set("Accept", manifestAcceptHeader())
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return zero, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := HTTPSuccess(resp, route.SuccessCodes...); err != nil {
		return zero, err
	}
	var dgst digest.Digest
	if parsed, err := digest.Parse(tagOrDigest); err == nil {
		dgst = parsed
	}
	desc, err := descriptorFromResponse(resp, dgst)
	if err != nil {
		return zero, err
	}
	return desc, nil
}

// StatManifest returns the descriptor for a given maniifest.
// Only the MediaType, dgst and Size fields will be filled out.
func (c *RegistryClient) StatManifest(ctx context.Context, repo string, dgst digest.Digest) (v1.Descriptor, error) {
	return c.headManifest(ctx, repo, dgst.String())
}

// StatTag returns the descriptor for a given tag.
// Only the MediaType, dgst and Size fields will be filled out.
func (c *RegistryClient) StatTag(ctx context.Context, repo string, tag string) (v1.Descriptor, error) {
	return c.headManifest(ctx, repo, tag)
}

// StatBlob returns the descriptor for a given blob digest.
// Only the MediaType, dgst and Size fields will be filled out.
func (c *RegistryClient) StatBlob(ctx context.Context, repo string, dgst digest.Digest) (v1.Descriptor, error) {
	var zero v1.Descriptor
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	route := RouteBlobsHead
	request, err := c.builder().WithName(repo).WithDigest(dgst).BuildRequest(ctx, route)
	if err != nil {
		return zero, err
	}
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return zero, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := HTTPSuccess(resp, route.SuccessCodes...); err != nil {
		return zero, err
	}
	desc, err := descriptorFromResponse(resp, dgst)
	if err != nil {
		return zero, err
	}
	return desc, nil
}

// GetBlob returns the content of the blob with the given digest.
// The context also controls the lifetime of the returned DescribableReadCloser.
func (c *RegistryClient) GetBlob(ctx context.Context, repo string, dgst digest.Digest) (DescribableReadCloser, error) {
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	route := RouteBlobsGet
	request, err := c.builder().WithName(repo).WithDigest(dgst).BuildRequest(ctx, route)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // resp.Body is returned as a wrap
	if err != nil {
		return nil, err
	}
	if err := HTTPSuccess(resp, route.SuccessCodes...); err != nil {
		return nil, err
	}
	var desc v1.Descriptor
	if resp.ContentLength == -1 {
		desc, err = c.StatBlob(ctx, repo, dgst)
	} else {
		desc, err = descriptorFromResponse(resp, dgst)
	}
	if err != nil {
		xio.CloseAndSkipError(resp.Body)
		return nil, err
	}
	return NewDescribableReadCloser(resp.Body, desc), nil
}

// GetBlobRange is like GetBlob but asks to get only the given range of bytes from the blob,
// starting at "start" offset, up to but not including "end" offset.
// If "end" offset is negative or exceeds the actual size of the blob, GetBlobRange will
// return all the data starting from "start" offset.
// The context also controls the lifetime of the returned DescribableReadCloser.
func (c *RegistryClient) GetBlobRange(ctx context.Context, repo string, dgst digest.Digest, start, end int64) (DescribableReadCloser, error) {
	if start < 0 {
		start = 0
	}
	if start == 0 && end < 0 {
		return c.GetBlob(ctx, repo, dgst)
	}
	if end < start+1 {
		return nil, fmt.Errorf("invalid range, start offset %d must be less than end offset %d", start, end)
	}
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	route := RouteBlobsGet
	request, err := c.builder().WithName(repo).WithDigest(dgst).BuildRequest(ctx, route)
	if err != nil {
		return nil, err
	}
	if end < 0 {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", start))
	} else {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end-1))
	}
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // resp.Body is returned as a wrap
	if err != nil {
		return nil, err
	}
	// allowed with 200 and 206
	allowedCodes := slices.Clone(route.SuccessCodes)
	allowedCodes = append(allowedCodes, http.StatusPartialContent)
	if err := HTTPSuccess(resp, allowedCodes...); err != nil {
		return nil, err
	}
	desc, err := descriptorFromResponse(resp, dgst)
	if err != nil {
		return nil, err
	}
	return NewDescribableReadCloser(resp.Body, desc), nil
}

//nolint:gocognit
func descriptorFromResponse(resp *http.Response, knownDigest digest.Digest) (v1.Descriptor, error) {
	var zero v1.Descriptor
	// check Content-Type
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		// FIXME(wuxler): should we handle the error when the Content-Type is invalid ?
		mediaType = manifest.DefaultMediaType
	}
	// check Content-Length
	var size int64
	if resp.StatusCode == http.StatusPartialContent {
		contentRange := resp.Header.Get("Content-Range")
		if contentRange == "" {
			return zero, makeError(resp, errors.New("missing 'Content-Range' header in partial content response"))
		}
		i := strings.LastIndex(contentRange, "/")
		if i == -1 {
			return zero, makeError(resp, fmt.Errorf("invalid 'Content-Range' header: %q", contentRange))
		}
		contentSize, err := strconv.ParseInt(contentRange[i+1:], 10, 64)
		if err != nil {
			return zero, makeError(resp, fmt.Errorf("invalid 'Content-Range' header: %q", contentRange))
		}
		size = contentSize
	} else {
		if resp.ContentLength < 0 {
			return v1.Descriptor{}, makeError(resp, errors.New("missing 'Content-Length' header"))
		}
		size = resp.ContentLength
	}

	// check digest
	var serverSideDigest digest.Digest
	if s := resp.Header.Get(dockerContentDigestHeader); s != "" {
		dgst, err := digest.Parse(s)
		if err != nil {
			return zero, makeError(resp, fmt.Errorf("invalid '%s' header: %q: %w", dockerContentDigestHeader, s, err))
		}
		serverSideDigest = dgst
	}
	if len(knownDigest) > 0 && serverSideDigest != knownDigest {
		return zero, makeError(resp, fmt.Errorf("digest mismatch: known=%q, server=%q", knownDigest, serverSideDigest))
	}

	contentDigest := serverSideDigest
	if len(contentDigest) == 0 {
		if resp.Request.Method == http.MethodHead {
			if len(knownDigest) == 0 {
				return zero, makeError(resp, fmt.Errorf("missing both '%s' header and known digest in HEAD request", dockerContentDigestHeader))
			}
		} else {
			// FIXME(wuxler): should we calculate digest from body here?
			contentDigest = knownDigest
		}
	}

	desc := v1.Descriptor{
		MediaType: mediaType,
		Digest:    contentDigest,
		Size:      size,
	}
	return desc, nil
}

func manifestAcceptHeader(mediaTypes ...string) string {
	if len(mediaTypes) == 0 {
		mediaTypes = defaultRequestedManifestMediaTypes
	}
	return strings.Join(mediaTypes, ", ")
}
