package distribution

import (
	"context"
	"fmt"
	"io"
	"net/http"
	stdurl "net/url"
	"regexp"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/spf13/cast"
)

// RouteDescriptor is a descriptor for a route endpoint api.
type RouteDescriptor struct {
	// ID is the unique identifier for the route endpoint api.
	ID string
	// Method is the HTTP method for the route endpoint api.
	Method string
	// PathPattern is the HTTP path pattern for the route endpoint api.
	PathPattern string
	// QueryParams is the list of query parameters for the route endpoint api.
	QueryParams map[string]string
	// SuccessCodes is the list of HTTP status codes that indicate success.
	SuccessCodes []int
	// FailureCodes is the list of HTTP status codes that indicate failure.
	FailureCodes []int
}

// ping, tags, referrers related endpoints.
var (
	// RoutePing is the route descriptor to ping registry.
	RoutePing = RouteDescriptor{
		ID:           "end-1",
		Method:       http.MethodGet,
		PathPattern:  "/v2/",
		SuccessCodes: []int{http.StatusOK},                                // 200
		FailureCodes: []int{http.StatusNotFound, http.StatusUnauthorized}, // 404/401
	}
	// RouteRepositoriesList is the route descriptor for the repositories to list.
	RouteRepositoriesList = RouteDescriptor{
		ID:           "end-x-1",
		Method:       http.MethodGet,
		PathPattern:  "/v2/_catalog",
		SuccessCodes: []int{http.StatusOK},                                   // 200
		FailureCodes: []int{http.StatusForbidden, http.StatusNotImplemented}, // 403/501
	}
	// RouteTagsList is the route descriptor for the tags to list.
	RouteTagsList = RouteDescriptor{
		ID:           "end-8a",
		Method:       http.MethodGet,
		PathPattern:  "/v2/{name}/tags/list",
		SuccessCodes: []int{http.StatusOK},       // 200
		FailureCodes: []int{http.StatusNotFound}, // 404
	}
	// RouteTagsListPager is the route descriptor for the tags to list with page query parameters.
	// Example: GET /v2/{name}/tags/list?n={integer}&last={tagname}
	RouteTagsListPager = RouteDescriptor{
		ID:          "end-8b",
		Method:      http.MethodGet,
		PathPattern: "/v2/{name}/tags/list",
		QueryParams: map[string]string{
			"n":    "{integer}",
			"last": "{last}",
		},
		SuccessCodes: []int{http.StatusOK},       // 200
		FailureCodes: []int{http.StatusNotFound}, // 404
	}
	// RouteReferrersList is the route descriptor for the referrers to list.
	RouteReferrersList = RouteDescriptor{
		ID:           "end-12a",
		Method:       http.MethodGet,
		PathPattern:  "/v2/{name}/referrers/{digest}",
		SuccessCodes: []int{http.StatusOK},                              // 200
		FailureCodes: []int{http.StatusNotFound, http.StatusBadRequest}, // 404/400
	}
	// RouteReferrersListByType is the route descriptor for the referrers to list by artifact type.
	// Example: GET /v2/{name}/referrers/{digest}?artifactType={artifactType}
	RouteReferrersListByType = RouteDescriptor{
		ID:          "end-12b",
		Method:      http.MethodGet,
		PathPattern: "/v2/{name}/referrers/{digest}",
		QueryParams: map[string]string{
			"artifactType": "{artifact_type}",
		},
		SuccessCodes: []int{http.StatusOK},                              // 200
		FailureCodes: []int{http.StatusNotFound, http.StatusBadRequest}, // 404/400
	}
)

// manifests related endpoints.
var (
	// RouteManifestsGet is the route descriptor for the manifests to fetch.
	RouteManifestsGet = RouteDescriptor{
		ID:           "end-3",
		Method:       http.MethodGet,
		PathPattern:  "/v2/{name}/manifests/{reference}",
		SuccessCodes: []int{http.StatusOK},       // 200
		FailureCodes: []int{http.StatusNotFound}, // 404
	}
	// RouteManifestsHead is the route descriptor for the manifests to stat.
	RouteManifestsHead = RouteDescriptor{
		ID:           "end-3",
		Method:       http.MethodHead,
		PathPattern:  "/v2/{name}/manifests/{reference}",
		SuccessCodes: []int{http.StatusOK},       // 200
		FailureCodes: []int{http.StatusNotFound}, // 404
	}
	// RouteManifestsPut is the route descriptor for the manifests to upload.
	RouteManifestsPut = RouteDescriptor{
		ID:           "end-7",
		Method:       http.MethodPut,
		PathPattern:  "/v2/{name}/manifests/{reference}",
		SuccessCodes: []int{http.StatusCreated},  // 201
		FailureCodes: []int{http.StatusNotFound}, // 404
	}
	// RouteManifestsDelete is the route descriptor for the manifests to delete.
	RouteManifestsDelete = RouteDescriptor{
		ID:           "end-9",
		Method:       http.MethodDelete,
		PathPattern:  "/v2/{name}/manifests/{reference}",
		SuccessCodes: []int{http.StatusAccepted}, // 202
		FailureCodes: []int{
			http.StatusNotFound,
			http.StatusBadRequest,
			http.StatusMethodNotAllowed,
		}, // 404/400/405
	}
)

// blobs related endpoints.
var (
	// RouteBlobsGet is the route descriptor for the blobs to fetch.
	RouteBlobsGet = RouteDescriptor{
		ID:           "end-2",
		Method:       http.MethodGet,
		PathPattern:  "/v2/{name}/manifests/{digest}",
		SuccessCodes: []int{http.StatusOK},       // 200
		FailureCodes: []int{http.StatusNotFound}, // 404
	}
	// RouteBlobsHead is the route descriptor for the blobs to stat.
	RouteBlobsHead = RouteDescriptor{
		ID:           "end-2",
		Method:       http.MethodHead,
		PathPattern:  "/v2/{name}/manifests/{digest}",
		SuccessCodes: []int{http.StatusOK},       // 200
		FailureCodes: []int{http.StatusNotFound}, // 404
	}
	// RouteBlobsUploadStart is the route descriptor for the blobs to start blob uploads.
	RouteBlobsUploadStart = RouteDescriptor{
		ID:           "end-4a",
		Method:       http.MethodPost,
		PathPattern:  "/v2/{name}/blobs/uploads/",
		SuccessCodes: []int{http.StatusAccepted}, // 202
		FailureCodes: []int{http.StatusNotFound}, // 404
	}
	// RouteBlobsUploadBlob is the route descriptor for the blobs to upload blobs.
	// Example: POST /v2/{name}/blobs/uploads/?digest={digest}
	RouteBlobsUploadBlob = RouteDescriptor{
		ID:          "end-4b",
		Method:      http.MethodPost,
		PathPattern: "/v2/{name}/blobs/uploads/",
		QueryParams: map[string]string{
			"digest": "{digest}",
		},
		SuccessCodes: []int{http.StatusCreated, http.StatusAccepted},    // 201/202
		FailureCodes: []int{http.StatusNotFound, http.StatusBadRequest}, // 404/400
	}
	// RouteBlobsUploadChunk is the route descriptor for the blobs to upload chunks.
	RouteBlobsUploadChunk = RouteDescriptor{
		ID:           "end-5",
		Method:       http.MethodPatch,
		PathPattern:  "/v2/{name}/blobs/uploads/{reference}",
		SuccessCodes: []int{http.StatusAccepted}, // 202
		FailureCodes: []int{
			http.StatusNotFound,
			http.StatusRequestedRangeNotSatisfiable,
		}, // 404/416
	}
	// RouteBlobsUploadComplete is the route descriptor for the blobs to complete blob uploads.
	// Example: PUT /v2/{name}/blobs/uploads/{reference}?digest={digest}
	RouteBlobsUploadComplete = RouteDescriptor{
		ID:          "end-6",
		Method:      http.MethodPut,
		PathPattern: "/v2/{name}/blobs/uploads/{reference}",
		QueryParams: map[string]string{
			"digest": "{digest}",
		},
		SuccessCodes: []int{http.StatusCreated},                         // 201
		FailureCodes: []int{http.StatusNotFound, http.StatusBadRequest}, // 404/400
	}
	// RouteBlobsDelete is the route descriptor for the blobs to delete.
	RouteBlobsDelete = RouteDescriptor{
		ID:           "end-10",
		Method:       http.MethodDelete,
		PathPattern:  "/v2/{name}/blobs/{digest}",
		SuccessCodes: []int{http.StatusAccepted},                              // 202
		FailureCodes: []int{http.StatusNotFound, http.StatusMethodNotAllowed}, // 404/405
	}
	// RouteBlobsMount is the route descriptor for blobs to mount.
	// Example: POST /v2/{name}/blobs/uploads/?mount={digest}&from={other_name}
	RouteBlobsMount = RouteDescriptor{
		ID:          "end-11",
		Method:      http.MethodPost,
		PathPattern: "/v2/{name}/blobs/uploads/",
		QueryParams: map[string]string{
			"mount": "{digest}",
			"from":  "{from_name}",
		},
		SuccessCodes: []int{http.StatusCreated},  // 201
		FailureCodes: []int{http.StatusNotFound}, // 404
	}
	// RouteBlobsStatUploadsInfo is the route descriptor for the blobs to stat uploads info.
	RouteBlobsStatUploadsInfo = RouteDescriptor{
		ID:           "end-13",
		Method:       http.MethodGet,
		PathPattern:  "/v2/{name}/blobs/uploads/{session_id}",
		SuccessCodes: []int{http.StatusNoContent}, // 204
		FailureCodes: []int{http.StatusNotFound},  // 404
	}
)

type RouteBuilder struct {
	BaseURL      string
	Name         string
	Reference    string
	Digest       digest.Digest
	SessionID    string
	FromName     string
	ArtifactType string
	PageSize     int
	Last         string
	Body         io.Reader
}

func (rb *RouteBuilder) WithBaseURL(base string) *RouteBuilder {
	rb.BaseURL = base
	return rb
}

func (rb *RouteBuilder) WithName(name string) *RouteBuilder {
	rb.Name = name
	return rb
}

func (rb *RouteBuilder) WithReference(reference string) *RouteBuilder {
	rb.Reference = reference
	return rb
}

func (rb *RouteBuilder) WithDigest(dgst digest.Digest) *RouteBuilder {
	rb.Digest = dgst
	return rb
}

func (rb *RouteBuilder) WithSessionID(sessionID string) *RouteBuilder {
	rb.SessionID = sessionID
	return rb
}

func (rb *RouteBuilder) WithFromName(name string) *RouteBuilder {
	rb.FromName = name
	return rb
}

func (rb *RouteBuilder) WithArtifactType(artifactType string) *RouteBuilder {
	rb.ArtifactType = artifactType
	return rb
}

func (rb *RouteBuilder) WithPageSize(size int) *RouteBuilder {
	rb.PageSize = size
	return rb
}

func (rb *RouteBuilder) WithLastOffset(last string) *RouteBuilder {
	rb.Last = last
	return rb
}

func (rb *RouteBuilder) WithBody(body io.Reader) *RouteBuilder {
	rb.Body = body
	return rb
}

func (rb *RouteBuilder) Endpoint(route RouteDescriptor) Endpoint {
	return &routeEndpoint{
		route:   route,
		builder: rb,
	}
}

func (rb *RouteBuilder) replace(pattern string) string {
	// replace known path params
	replacements := map[string]string{
		"{name}":          rb.Name,
		"{reference}":     rb.Reference,
		"{digest}":        rb.Digest.String(),
		"{session_id}":    rb.SessionID,
		"{from_name}":     rb.FromName,
		"{artifact_type}": rb.ArtifactType,
		"{integer}":       cast.ToString(rb.PageSize),
		"{last}":          rb.Last,
	}
	for k, v := range replacements {
		if v != "" {
			pattern = strings.Replace(pattern, k, v, -1)
		}
	}
	return pattern
}

func (rb *RouteBuilder) buildPath(route RouteDescriptor) (string, error) {
	path := rb.replace(route.PathPattern)
	if err := validateRoutePath(path); err != nil {
		return "", err
	}
	return path, nil
}

func (rb *RouteBuilder) buildURL(route RouteDescriptor) (*stdurl.URL, error) {
	routePath, err := rb.buildPath(route)
	if err != nil {
		return nil, err
	}
	urlStr := strings.TrimSuffix(rb.BaseURL, "/") + "/" + strings.TrimPrefix(routePath, "/")
	url, err := stdurl.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	query := url.Query()
	for k, v := range route.QueryParams {
		v = rb.replace(v)
		query.Set(k, v)
	}
	url.RawQuery = query.Encode()
	return url, nil
}

func (rb *RouteBuilder) buildRequest(ctx context.Context, route RouteDescriptor) (*http.Request, error) {
	url, err := rb.buildURL(route)
	if err != nil {
		return nil, err
	}
	body := rb.Body
	if body == nil {
		body = http.NoBody
	}
	return http.NewRequestWithContext(ctx, route.Method, url.String(), body)
}

var (
	routePathValidatePattern = `\{name\}|\{reference\}|\{digest\}|\{session_id\}|\{from_name\}|\{artifact_type\}|\{integer\}|\{last\}|/{2,}`
	routePathValidateRegex   = regexp.MustCompile(routePathValidatePattern)
)

// Validate returns an error if the request is invalid.
func validateRoutePath(path string) error {
	matches := routePathValidateRegex.FindAllString(path, -1)
	if len(matches) == 0 {
		return nil
	}
	return fmt.Errorf("invalid route path: %s", path)
}

type Endpoint interface {
	Descriptor() RouteDescriptor
	BuildPath() (string, error)
	BuildURL() (*stdurl.URL, error)
	BuildRequest(ctx context.Context) (*http.Request, error)
}

type routeEndpoint struct {
	route   RouteDescriptor
	builder *RouteBuilder
}

func (endpoint *routeEndpoint) Descriptor() RouteDescriptor {
	return endpoint.route
}
func (endpoint *routeEndpoint) BuildPath() (string, error) {
	return endpoint.builder.buildPath(endpoint.route)
}
func (endpoint *routeEndpoint) BuildURL() (*stdurl.URL, error) {
	return endpoint.builder.buildURL(endpoint.route)
}
func (endpoint *routeEndpoint) BuildRequest(ctx context.Context) (*http.Request, error) {
	return endpoint.builder.buildRequest(ctx, endpoint.route)
}
