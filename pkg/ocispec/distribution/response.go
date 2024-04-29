package distribution

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/samber/lo"
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
		return makeError(resp, fmt.Errorf("%s: unable to read response body: %w", errMsg, err))
	}
	if len(content) > 0 {
		return makeError(resp, fmt.Errorf("%s: %s", errMsg, string(content)))
	}
	return makeError(resp, errors.New(errMsg))
}

func makeError(resp *http.Response, err error) error {
	if resp == nil {
		return err
	}
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s %s: %w", resp.Request.Method, resp.Request.URL.Redacted(), err)
}
