package client

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/image/manifest"
	"github.com/wuxler/ruasec/pkg/image/name"
	"github.com/wuxler/ruasec/pkg/ocispec/authn"
	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
	"github.com/wuxler/ruasec/pkg/util/xio"
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

type Registry struct {
	HTTPClient *Factory
	registry   name.Registry
}

func (c *Registry) builder() *distribution.RouteBuilder {
	b := &distribution.RouteBuilder{}
	return b.WithBaseURL(fmt.Sprintf("%s://%s", c.registry.Scheme(), c.registry.Hostname()))
}

// Ping checks if the storage is reachable.
func (c *Registry) Ping(ctx context.Context) error {
	route := distribution.RoutePing
	request, err := c.builder().BuildRequest(ctx, route)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	return distribution.HTTPSuccess(resp, route.SuccessCodes...)
}

// GetManifest returns the contents of the manifest with the given tag or digest.
// The context also controls the lifetime of the returned DescribableReadCloser.
func (c *Registry) GetManifest(ctx context.Context, repo string, tagOrDigest string) (distribution.DescribableReadCloser, error) {
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	route := distribution.RouteManifestsGet
	request, err := c.builder().WithName(repo).WithReference(tagOrDigest).BuildRequest(ctx, route)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", manifestAcceptHeader())
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // resp.Body is returned as a wrap
	if err != nil {
		return nil, err
	}
	if err := distribution.HTTPSuccess(resp, route.SuccessCodes...); err != nil {
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
	return distribution.NewDescribableReadCloser(resp.Body, desc), nil
}

// StatManifest returns the descriptor for a given tag or digest.
// Only the MediaType, dgst and Size fields will be filled out.
func (c *Registry) StatManifest(ctx context.Context, repo string, tagOrDigest string) (imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	route := distribution.RouteManifestsHead
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
	if err := distribution.HTTPSuccess(resp, route.SuccessCodes...); err != nil {
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

// DeleteManifest deletes the manifest with the given digest in the given repository.
func (c *Registry) DeleteManifest(ctx context.Context, repo string, dgst digest.Digest) error {
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionDelete))
	route := distribution.RouteManifestsDelete
	request, err := c.builder().WithName(repo).WithReference(dgst.String()).BuildRequest(ctx, route)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := distribution.HTTPSuccess(resp, route.SuccessCodes...); err != nil {
		return err
	}
	return nil
}

// PushManifest pushes a manifest with the given media type and contents.
// If mediaType is not specified, "application/octet-stream" is used.
//
// It returns a descriptor suitable for accessing the manifest.
func (c *Registry) PushManifest(ctx context.Context, repo string, tag string, content []byte, mediaType string) (imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor
	desc := manifest.NewDescriptorFromBytes(mediaType, content)
	// pushing usually requires both pull and push actions.
	// Reference: https://github.com/distribution/distribution/blob/v2.7.1/registry/handlers/app.go#L921-L930
	ctx = authn.AppendScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull, authn.ActionPush))
	route := distribution.RouteManifestsPut
	ref := tag
	if ref == "" {
		ref = desc.Digest.String()
	}
	request, err := c.builder().
		WithName(repo).
		WithReference(ref).
		WithBody(bytes.NewReader(content)).
		BuildRequest(ctx, route)
	if err != nil {
		return zero, err
	}
	request.Header.Set("Content-Type", desc.MediaType)
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return zero, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := distribution.HTTPSuccess(resp, route.SuccessCodes...); err != nil {
		return zero, err
	}
	return desc, nil
}

// StatBlob returns the descriptor for a given blob digest.
// Only the MediaType, dgst and Size fields will be filled out.
func (c *Registry) StatBlob(ctx context.Context, repo string, dgst digest.Digest) (imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	route := distribution.RouteBlobsHead
	request, err := c.builder().WithName(repo).WithDigest(dgst).BuildRequest(ctx, route)
	if err != nil {
		return zero, err
	}
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return zero, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := distribution.HTTPSuccess(resp, route.SuccessCodes...); err != nil {
		return zero, err
	}
	desc, err := distribution.DescriptorFromResponse(resp, dgst)
	if err != nil {
		return zero, err
	}
	return desc, nil
}

// GetBlob returns the content of the blob with the given digest.
// The context also controls the lifetime of the returned DescribableReadCloser.
func (c *Registry) GetBlob(ctx context.Context, repo string, dgst digest.Digest) (distribution.DescribableReadCloser, error) {
	ctx = authn.WithScopes(ctx, authn.RepositoryScope(repo, authn.ActionPull))
	route := distribution.RouteBlobsGet
	request, err := c.builder().WithName(repo).WithDigest(dgst).BuildRequest(ctx, route)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(request) //nolint:bodyclose // resp.Body is returned as a wrap
	if err != nil {
		return nil, err
	}
	if err := distribution.HTTPSuccess(resp, route.SuccessCodes...); err != nil {
		return nil, err
	}
	var desc imgspecv1.Descriptor
	if resp.ContentLength == -1 {
		desc, err = c.StatBlob(ctx, repo, dgst)
	} else {
		desc, err = distribution.DescriptorFromResponse(resp, dgst)
	}
	if err != nil {
		xio.CloseAndSkipError(resp.Body)
		return nil, err
	}
	return distribution.NewDescribableReadCloser(resp.Body, desc), nil
}

// GetBlobRange is like GetBlob but asks to get only the given range of bytes from the blob,
// starting at "start" offset, up to but not including "end" offset.
// If "end" offset is negative or exceeds the actual size of the blob, GetBlobRange will
// return all the data starting from "start" offset.
// The context also controls the lifetime of the returned DescribableReadCloser.
func (c *Registry) GetBlobRange(ctx context.Context, repo string, dgst digest.Digest, start, end int64) (distribution.DescribableReadCloser, error) {
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
	route := distribution.RouteBlobsGet
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
	if err := distribution.HTTPSuccess(resp, allowedCodes...); err != nil {
		return nil, err
	}
	desc, err := distribution.DescriptorFromResponse(resp, dgst)
	if err != nil {
		return nil, err
	}
	return distribution.NewDescribableReadCloser(resp.Body, desc), nil
}

// // DeleteBlob deletes the blob with the given digest in the given repository.
// DeleteBlob(ctx context.Context, repo string, dgst digest.Digest) error

func manifestAcceptHeader(mediaTypes ...string) string {
	if len(mediaTypes) == 0 {
		mediaTypes = defaultRequestedManifestMediaTypes
	}
	return strings.Join(mediaTypes, ", ")
}
