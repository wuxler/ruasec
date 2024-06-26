package distribution

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/samber/lo"

	"github.com/wuxler/ruasec/pkg/image/manifest"
)

const (
	dockerContentDigestHeader = "Docker-Content-Digest"
)

// maxErrorBytes specifies the default limit on how many response bytes are
// allowed in the server's error response. A typical error message is around
// 200 bytes. Hence, 8 KiB should be sufficient.
const maxErrorBytes int64 = 8 * 1024 // 8 KiB

// HTTPSuccess returns nil if the response status code is allowed, or an
// error parsed from response.
//
// NOTE: This method will try to read resp.Body but not close it, so that the
// caller are expected to close resp.Body manully.
func HTTPSuccess(resp *http.Response, allowedCodes ...int) error {
	if resp == nil {
		return errors.New("response is nil")
	}
	allowedCodes = append(allowedCodes, http.StatusOK)
	allowedCodes = lo.Uniq(allowedCodes)
	if lo.Contains(allowedCodes, resp.StatusCode) {
		return nil
	}
	errMsg := fmt.Sprintf("missing unexpected status code: %d", resp.StatusCode)

	body := resp.Body
	if body == nil {
		body = http.NoBody
	}
	r := io.LimitReader(body, maxErrorBytes)
	content, err := io.ReadAll(r)
	if err != nil {
		return MakeError(resp, fmt.Errorf("%s: unable to read response body: %w", errMsg, err))
	}
	if len(content) > 0 {
		return MakeError(resp, fmt.Errorf("%s: %s", errMsg, string(content)))
	}
	return MakeError(resp, errors.New(errMsg))
}

func MakeError(resp *http.Response, err error) error {
	if resp == nil {
		return err
	}
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s %s: %w", resp.Request.Method, resp.Request.URL.Redacted(), err)
}

//nolint:gocognit
func DescriptorFromResponse(resp *http.Response, knownDigest digest.Digest) (imgspecv1.Descriptor, error) {
	var zero imgspecv1.Descriptor
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
			return zero, MakeError(resp, errors.New("missing 'Content-Range' header in partial content response"))
		}
		i := strings.LastIndex(contentRange, "/")
		if i == -1 {
			return zero, MakeError(resp, fmt.Errorf("invalid 'Content-Range' header: %q", contentRange))
		}
		contentSize, err := strconv.ParseInt(contentRange[i+1:], 10, 64)
		if err != nil {
			return zero, MakeError(resp, fmt.Errorf("invalid 'Content-Range' header: %q", contentRange))
		}
		size = contentSize
	} else {
		if resp.ContentLength < 0 {
			return imgspecv1.Descriptor{}, MakeError(resp, errors.New("missing 'Content-Length' header"))
		}
		size = resp.ContentLength
	}

	// check digest
	var serverSideDigest digest.Digest
	if s := resp.Header.Get(dockerContentDigestHeader); s != "" {
		dgst, err := digest.Parse(s)
		if err != nil {
			return zero, MakeError(resp, fmt.Errorf("invalid '%s' header: %q: %w", dockerContentDigestHeader, s, err))
		}
		serverSideDigest = dgst
	}
	if len(knownDigest) > 0 && serverSideDigest != knownDigest {
		return zero, MakeError(resp, fmt.Errorf("digest mismatch: known=%q, server=%q", knownDigest, serverSideDigest))
	}

	contentDigest := serverSideDigest
	if len(contentDigest) == 0 {
		if resp.Request.Method == http.MethodHead {
			if len(knownDigest) == 0 {
				return zero, MakeError(resp, fmt.Errorf("missing both '%s' header and known digest in HEAD request", dockerContentDigestHeader))
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
