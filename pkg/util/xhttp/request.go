package xhttp

import (
	"fmt"
	"net/http"
)

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
