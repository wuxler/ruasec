package distribution

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/opencontainers/go-digest"
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
			"last": "{tagname}",
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
			"artifactType": "{artifactType}",
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
			"from":  "{name}",
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

var (
	routePathValidatePattern = `\{name\}|\{reference\}|\{digest\}|\{session_id\}|/{2,}`
	routePathValidateRegex   = regexp.MustCompile(routePathValidatePattern)
)

type routeBuilder struct {
	BaseURL   string
	Name      string
	Reference string
	Digest    digest.Digest
	SessionID string
	Body      io.Reader
}

func (rb *routeBuilder) WithBaseURL(base string) *routeBuilder {
	rb.BaseURL = base
	return rb
}

func (rb *routeBuilder) WithName(name string) *routeBuilder {
	rb.Name = name
	return rb
}

func (rb *routeBuilder) WithReference(reference string) *routeBuilder {
	rb.Reference = reference
	return rb
}

func (rb *routeBuilder) WithDigest(dgst digest.Digest) *routeBuilder {
	rb.Digest = dgst
	return rb
}

func (rb *routeBuilder) WithSessionID(sessionID string) *routeBuilder {
	rb.SessionID = sessionID
	return rb
}

func (rb *routeBuilder) WithBody(body io.Reader) *routeBuilder {
	rb.Body = body
	return rb
}

func (rb *routeBuilder) BuildPath(route RouteDescriptor) (string, error) {
	path := route.PathPattern
	// replace known path params
	replacements := map[string]string{
		"{name}":       rb.Name,
		"{reference}":  rb.Reference,
		"{digest}":     rb.Digest.String(),
		"{session_id}": rb.SessionID,
	}
	for k, v := range replacements {
		if v != "" {
			path = strings.Replace(path, k, v, -1)
		}
	}
	if err := validateRoutePath(path); err != nil {
		return "", err
	}
	return path, nil
}

func (rb *routeBuilder) MustBuildPath(route RouteDescriptor) string {
	path, err := rb.BuildPath(route)
	if err != nil {
		panic(err)
	}
	return path
}

func (rb *routeBuilder) BuildRequest(ctx context.Context, route RouteDescriptor) (*http.Request, error) {
	routePath, err := rb.BuildPath(route)
	if err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(rb.BaseURL, "/")
	path := strings.TrimPrefix(routePath, "/")
	url := base + "/" + path
	body := rb.Body
	if body == nil {
		body = http.NoBody
	}
	return http.NewRequestWithContext(ctx, route.Method, url, body)
}

// Validate returns an error if the request is invalid.
func validateRoutePath(path string) error {
	matches := routePathValidateRegex.FindAllString(path, -1)
	if len(matches) == 0 {
		return nil
	}
	return fmt.Errorf("invalid route path: %s", path)
}
