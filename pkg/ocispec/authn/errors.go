package authn

import "errors"

var (
	// ErrUnsupported is returned if the operation is not supported.
	ErrUnsupported = errors.ErrUnsupported
	// ErrNotFound is returned if the resource is not found.
	ErrNotFound = errors.New("not found")
	// ErrBadCredentialFormat is returned when the credential format is bad.
	ErrBadCredentialFormat = errors.New("bad credential format")
	// ErrNoToken is returned if a request is successful but the body does not
	// contain an authorization token.
	ErrNoToken = errors.New("authorization server did not include a token in the response")
)
