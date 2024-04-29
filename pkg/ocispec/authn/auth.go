package authn

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var (
	_ Authorizer = Anonymous{}
	_ Authorizer = Basic{}
	_ Authorizer = Token{}
	_ Authorizer = AuthorizeFunc(nil)
)

// Authorizer authorizes HTTP requests.
type Authorizer interface {
	Authorize(req *http.Request) error
}

// AuthorizeFunc is a function that implements Authorizer.
type AuthorizeFunc func(req *http.Request) error

func (fn AuthorizeFunc) Authorize(req *http.Request) error {
	return fn(req)
}

const (
	// defaultTokenExpires specifies the default token expires in second.
	// For compatibility with older clients, a token should never be returned with
	// less than 60 seconds to live.
	// References:
	// - https://docs.docker.com/registry/spec/auth/token/#token-response-fields
	defaultTokenExpires = 60
)

// NewAnonymous returns a anonymous type authorization.
func NewAnonymous() Anonymous {
	return Anonymous{}
}

// Anonymous is the anonymous type authorization.
type Anonymous struct{}

// Authorize implements [Authorizer] and do nothing.
func (auth Anonymous) Authorize(_ *http.Request) error {
	return nil
}

// NewBasic returns a basic type authorization.
func NewBasic(username string, password string) Basic {
	return Basic{
		Username: username,
		Password: password,
	}
}

// Basic is the basic type authorization.
type Basic struct {
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
}

// Authorize implements [Authorizer]. It will set the "Authorization" header in a HTTP
// request. The format of the header value is "Basic <value>" and the <value> is the
// base64 encoding of "<username>:<password>".
//
// NOTE: when any of username or password is empty, the "Authorization" header will
// not be set.
func (auth Basic) Authorize(req *http.Request) error {
	if auth.Username == "" || auth.Password == "" {
		return nil
	}
	req.SetBasicAuth(auth.Username, auth.Password)
	return nil
}

// NewToken returns a token type authorization.
func NewToken(token string) Token {
	return Token{
		Token:       token,
		AccessToken: token,
	}
}

// Token is the token type authorization.
type Token struct {
	Scheme      string    `json:"scheme,omitempty" yaml:"scheme,omitempty"` // default to "Bearer"
	Token       string    `json:"token,omitempty" yaml:"token,omitempty"`
	AccessToken string    `json:"access_token,omitempty" yaml:"access_token,omitempty"`
	ExpiresIn   int       `json:"expires_in,omitempty" yaml:"expires_in,omitempty"` // seconds
	IssuedAt    time.Time `json:"issued_at,omitempty" yaml:"issued_at,omitempty"`
}

// ExpiresAt returns the time that the token expires at. If IssuedAt is zero or not
// set, time.Now() will be used.
func (t Token) ExpiresAt() time.Time {
	issuedAt := t.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	return issuedAt.Add(time.Duration(t.ExpiresIn) * time.Second)
}

// Authorize implements [Authorizer]. It will set the "Authorization" header in a HTTP
// request. The format of the header value is "Bearer <value>".
//
// NOTE: when token is empty, the "Authorization" header will not be set.
func (t Token) Authorize(req *http.Request) error {
	if t.Token == "" && t.AccessToken == "" {
		return nil
	}
	scheme := t.Scheme
	if scheme == "" {
		scheme = "Bearer"
	}
	value := t.Token
	if value == "" {
		value = t.AccessToken
	}
	req.Header.Set("Authorization", scheme+" "+value)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler
func (t *Token) UnmarshalJSON(data []byte) error {
	type token Token

	var shadow token
	if err := json.Unmarshal(data, &shadow); err != nil {
		return fmt.Errorf("unable to decode token response: %w", err)
	}

	*t = Token(shadow)
	// `access_token` is equivalent to `token` and if both are specified
	// the choice is undefined.  Canonicalize `access_token` by sticking
	// things in `token`.
	if t.Token == "" {
		t.Token = t.AccessToken
	}
	if t.Token == "" {
		return ErrNoToken
	}
	if t.AccessToken == "" {
		t.AccessToken = t.Token
	}
	if t.ExpiresIn < defaultTokenExpires {
		// increasing token expiration to 60s
		t.ExpiresIn = defaultTokenExpires
	}

	return nil
}
