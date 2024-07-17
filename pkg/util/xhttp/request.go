package xhttp

import (
	"context"
	"fmt"
	"net/http"
)

type directRequestKey struct{}

// IsDirectRequest checks whether the request should send without authorization
// by the context of the request.
func IsDirectRequest(ctx context.Context) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	value := ctx.Value(directRequestKey{})
	return value != nil
}

// WithDirectRequest injects direct signal to tell the http client do request
// without authorization.
func WithDirectRequest(ctx context.Context) context.Context {
	return context.WithValue(ctx, directRequestKey{}, true)
}

// CheckRequestBodyRewindable tries to rewind the request body if exists.
func CheckRequestBodyRewindable(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if req.GetBody == nil {
		return fmt.Errorf("%s %s: request body is not rewindable", req.Method, req.URL.Redacted())
	}
	return nil
}
