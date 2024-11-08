package remote

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/http"
	stdurl "net/url"
	"strconv"
	"strings"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec"
	"github.com/wuxler/ruasec/pkg/util/xcontext"
	"github.com/wuxler/ruasec/pkg/util/xhttp"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

const (
	DockerContentDigestHeader = "Docker-Content-Digest"
)

var (
	defaultRequestedManifestMediaTypes = []string{
		ocispec.MediaTypeDockerV2S2Manifest,
		ocispec.MediaTypeDockerV2S2ManifestList,
		ocispec.MediaTypeImageManifest,
		ocispec.MediaTypeImageIndex,
		ocispec.MediaTypeDockerV2S1Manifest,
		ocispec.MediaTypeDockerV2S1SignedManifest,
	}
)

// ManifestAcceptHeader returns media types joined by ", " which is used to set the "Accept"
// request header. When the "mediaTypes" is empty, default media types used.
func ManifestAcceptHeader(mediaTypes ...string) string {
	if len(mediaTypes) == 0 {
		mediaTypes = defaultRequestedManifestMediaTypes
	}
	return strings.Join(mediaTypes, ", ")
}

// makeDescriptorFromResponse generates Descriptor from the http response.
//
//nolint:gocognit
func makeDescriptorFromResponse(resp *http.Response, knownDigest digest.Digest) (imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor
	// check Content-Type
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		// FIXME(wuxler): should we handle the error when the Content-Type is invalid ?
		mediaType = ocispec.DefaultMediaType
	}
	// check Content-Length
	var size int64
	if resp.StatusCode == http.StatusPartialContent {
		contentRange := resp.Header.Get("Content-Range")
		if contentRange == "" {
			return zero, xhttp.MakeResponseError(resp, errors.New("missing 'Content-Range' header in partial content response"))
		}
		i := strings.LastIndex(contentRange, "/")
		if i == -1 {
			return zero, xhttp.MakeResponseError(resp, fmt.Errorf("invalid 'Content-Range' header: %q", contentRange))
		}
		contentSize, err := strconv.ParseInt(contentRange[i+1:], 10, 64)
		if err != nil {
			return zero, xhttp.MakeResponseError(resp, fmt.Errorf("invalid 'Content-Range' header: %q", contentRange))
		}
		size = contentSize
	} else {
		if resp.ContentLength < 0 {
			return imgspecv1.Descriptor{}, xhttp.MakeResponseError(resp, errors.New("missing 'Content-Length' header"))
		}
		size = resp.ContentLength
	}

	// check digest
	var serverSideDigest digest.Digest
	if s := resp.Header.Get(DockerContentDigestHeader); s != "" {
		dgst, err := digest.Parse(s)
		if err != nil {
			return zero, xhttp.MakeResponseError(resp, fmt.Errorf("invalid '%s' header: %q: %w", DockerContentDigestHeader, s, err))
		}
		serverSideDigest = dgst
	}
	if len(knownDigest) > 0 && len(serverSideDigest) > 0 && serverSideDigest != knownDigest {
		return zero, xhttp.MakeResponseError(resp, fmt.Errorf("digest mismatch: known=%q, server=%q", knownDigest, serverSideDigest))
	}

	contentDigest := serverSideDigest
	if len(contentDigest) == 0 {
		if resp.Request.Method == http.MethodHead {
			if len(knownDigest) == 0 {
				return zero, xhttp.MakeResponseError(resp, fmt.Errorf("missing both '%s' header and known digest in HEAD request", DockerContentDigestHeader))
			}
		} else {
			// FIXME(wuxler): should we calculate digest from body here?
			contentDigest = knownDigest
		}
	}

	desc := imgspecv1.Descriptor{
		MediaType: mediaType,
		Digest:    contentDigest,
		Size:      size,
	}
	return desc, nil
}

// getNextPageURL checks if there  is a "Link" header in a http.Response which contains a
// link to the next page. If yes it returns the url.URL of the next page, otherwise returns
// nil and error.
func getNextPageURL(resp *http.Response) (*stdurl.URL, error) {
	link := resp.Header.Get("Link")
	if link == "" {
		return nil, errdefs.Newf(errdefs.ErrNotFound, "missing 'Link' header in response")
	}
	if link[0] != '<' {
		return nil, fmt.Errorf("invalid 'Link' header %q: missing '<' as the first character", link)
	}
	end := strings.Index(link, ">")
	if end < 0 {
		return nil, fmt.Errorf("invalid 'Link' header %q: missing '>' character", link)
	}
	link = link[1:end]

	linkURL, err := stdurl.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("invalid 'Link' header %q: %w", link, err)
	}
	if resp.Request == nil || resp.Request.URL == nil {
		return nil, errdefs.Newf(errdefs.ErrNotFound, "missing request URL in response")
	}
	linkURL = resp.Request.URL.ResolveReference(linkURL)
	return linkURL, nil
}

type directRequest bool

// WithDirectRequest injects direct signal to tell the http client do request
// without authorization.
func WithDirectRequest(ctx context.Context) context.Context {
	return xcontext.WithValue(ctx, directRequest(true))
}

// IsDirectRequest checks whether the request should send without authorization
// by the context of the request.
func IsDirectRequest(ctx context.Context) bool {
	value, ok := xcontext.GetValue[directRequest](ctx)
	if !ok {
		return false
	}
	return bool(value)
}

// DetectScheme sniffs the protocol of the target registry server is "http" or "https".
func DetectScheme(ctx context.Context, client xhttp.Client, addr string) (string, error) {
	ctx = WithDirectRequest(ctx)

	host, scheme, err := xhttp.ParseHostScheme(addr)
	if err != nil {
		return "", err
	}
	if scheme != "" {
		return scheme, nil
	}
	schemes := []string{"https", "http"}
	primary := &schemePinger{client: client, host: host, scheme: schemes[0]}
	fallback := &schemePinger{client: client, host: host, scheme: schemes[1]}
	isPrimary, err := xhttp.PingParallel(ctx, primary, fallback)
	if err != nil {
		return "", err
	}
	detected := schemes[0]
	if !isPrimary {
		detected = schemes[1]
	}
	return detected, nil
}

type schemePinger struct {
	client xhttp.Client
	host   string
	scheme string
}

func (p *schemePinger) String() string {
	return fmt.Sprintf("GET %s://%s/v2/", p.scheme, p.host)
}

func (p *schemePinger) Ping(ctx context.Context) (bool, error) {
	url := fmt.Sprintf("%s://%s/v2/", p.scheme, p.host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, err
	}
	resp, err := p.client.Do(req) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return false, xhttp.MakeRequestError(req, err)
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := xhttp.Success(resp, http.StatusUnauthorized); err != nil {
		return false, err
	}
	return true, nil
}
