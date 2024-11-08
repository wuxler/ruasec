package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	stdurl "net/url"
	"strings"
	"time"

	"github.com/wuxler/ruasec/pkg/appinfo"
	"github.com/wuxler/ruasec/pkg/ocispec/authn"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
	"github.com/wuxler/ruasec/pkg/util/xcache"
	"github.com/wuxler/ruasec/pkg/util/xhttp"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

var _ xhttp.Client = (*Client)(nil)

var (
	// defaultClientID specifies the default client ID used in token fetching.
	// See also TokenOptions.ClientID.
	defaultClientID = fmt.Sprintf("ruasec/%s", appinfo.ShortVersion())

	// maxAuthResponseBytes specifies the default limit on how many response bytes
	// are allowed in the server's response from authorization service servers.
	// A typical response message from authorization service servers is around 1 to
	// 4 KiB. Since the size of a token must be smaller than the HTTP header size
	// limit, which is usually 16 KiB. As specified by the distribution, the
	// response may contain 2 identical tokens, that is, 16 x 2 = 32 KiB.
	// Hence, 128 KiB should be sufficient.
	// See: https://distribution.github.io/distribution/spec/auth/token/
	maxAuthResponseBytes int64 = 128 * 1024 // 128 KiB

	defaultChallengeCache = xcache.NewDiscard[authn.Challenge]()
	defaultTokenCache     = xcache.NewDiscard[authn.Token]()
)

// ChallengeCache is the cache for the Challenge related to the registry.
type ChallengeCache = xcache.Cache[authn.Challenge]

// TokenCache is the cache for the Token related to the registry and scopes.
type TokenCache = xcache.Cache[authn.Token]

// NewClient returns the default client with the memory-based cache.
func NewClient() *Client {
	return &Client{
		ChallengeCache: xcache.NewMemory[authn.Challenge](),
		TokenCache:     xcache.NewMemory[authn.Token](),
	}
}

// Client implements [HTTPClient] interface for common distribution authentication spec.
type Client struct {
	// Client is the underlying HTTP client used to access the remote
	// server. If nil, http.DefaultClient is used.
	Client *http.Client

	// Header contains the custom headers to be added to each request.
	Header http.Header

	// AuthProvider returns AuthConfig related to the registry, which just returns an
	// empty AuthConfig when not found.
	AuthProvider AuthProvider

	// ChallengeCache is the cache for Challenge related to the registry, if not set,
	// default to a cache which will discard all operations.
	ChallengeCache ChallengeCache

	// TokenCache is the cache for Token related to the registry and scopes, if not set,
	// default to a cache which will discard all operations
	TokenCache TokenCache

	// TokenOptions is the options to fetch token for authorization.
	TokenOptions TokenOptions
}

// Do performs an HTTP request and returns an HTTP response with additinal processes like
// authenticating the request.
func (c *Client) Do(request *http.Request) (*http.Response, error) {
	resp, err := c.send(request)
	if err != nil {
		return nil, xhttp.MakeRequestError(request, err)
	}
	return resp, nil
}

// NewRegistry creates a client which implements distribution-spec interface to the remote registry.
func (c *Client) NewRegistry(ctx context.Context, name ocispecname.Registry) (*Registry, error) {
	scheme := name.Scheme()
	if scheme == "" || (scheme != "http" && scheme != "https") {
		scheme, err := DetectScheme(ctx, c, name.Hostname())
		if err != nil {
			return nil, err
		}
		name = name.WithScheme(scheme)
	}
	spec := &Registry{
		name:   name,
		client: c,
	}
	return spec, nil
}

// NewRepository creates a client which implements distribution-spec interface to the remote repository.
func (c *Client) NewRepository(ctx context.Context, name ocispecname.Repository) (*Repository, error) {
	registry, err := c.NewRegistry(ctx, name.Domain())
	if err != nil {
		return nil, err
	}
	return registry.RepositoryE(name.Path())
}

func (c *Client) send(request *http.Request) (*http.Response, error) {
	ctx := request.Context()
	request.Header = c.expandHeader(request.Header)

	if IsDirectRequest(ctx) {
		return c.client().Do(request)
	}

	if err := xhttp.CheckRequestBodyRewindable(request); err != nil {
		return nil, err
	}

	auth := authn.EmptyAuthConfig
	if c.AuthProvider != nil {
		auth = c.AuthProvider(ctx, request.URL.Host)
	}

	if err := c.setAuthorization(ctx, request, auth); err != nil {
		return nil, err
	}

	resp, err := c.client().Do(request)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	challenge := authn.ParseChallenge(resp.Header.Get("Www-Authenticate"))
	if challenge.Scheme != authn.SchemeBasic && challenge.Scheme != authn.SchemeBearer {
		return resp, nil
	}
	c.challengeCache().Set(ctx, c.challengeCacheKey(request), challenge)

	retryable, err := c.setAuthorizationWithChallenge(ctx, request, auth, challenge)
	if err != nil {
		xio.CloseAndSkipError(resp.Body)
		return nil, err
	}
	if !retryable {
		// could not acquire any more authorization than we had initially.
		return resp, nil
	}
	xio.CloseAndLogError(resp.Body)

	// retry request with authorization
	return c.client().Do(request)
}

func (c *Client) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return http.DefaultClient
}

func (c *Client) header() http.Header {
	if c.Header == nil {
		return make(http.Header)
	}
	return c.Header
}

func (c *Client) expandHeader(h http.Header) http.Header {
	if h == nil {
		h = make(http.Header)
	}
	additionalHeader := c.header()
	if len(additionalHeader) > 0 {
		for key, values := range additionalHeader {
			for _, value := range values {
				h.Add(key, value)
			}
		}
	}
	return h
}

func (c *Client) clientID() string {
	if c.TokenOptions.ClientID != "" {
		return c.TokenOptions.ClientID
	}
	return defaultClientID
}

func (c *Client) challengeCache() ChallengeCache {
	if c.ChallengeCache != nil {
		return c.ChallengeCache
	}
	return defaultChallengeCache
}

func (c *Client) tokenCache() TokenCache {
	if c.TokenCache != nil {
		return c.TokenCache
	}
	return defaultTokenCache
}

func (c *Client) challengeCacheKey(request *http.Request) string {
	return request.URL.Host
}

func (c *Client) tokenCacheKey(request *http.Request, scopes ...string) string {
	key := request.URL.Host
	scopeStr := strings.Join(scopes, ",")
	if scopeStr != "" {
		key = key + " " + scopeStr
	}
	return key
}

func (c *Client) setAuthorization(ctx context.Context, request *http.Request, auth authn.AuthConfig) error {
	if auth := request.Header.Get("Authorization"); auth != "" {
		return nil
	}
	challenge, ok := c.challengeCache().Get(ctx, c.challengeCacheKey(request))
	if !ok {
		return nil
	}
	switch challenge.Scheme {
	case authn.SchemeBasic:
		username, password := auth.Username, auth.Password
		if username != "" && password != "" {
			return authn.NewBasic(username, password).Authorize(request)
		}
	case authn.SchemeBearer:
		if auth.RegistryToken != "" {
			return authn.NewToken(auth.RegistryToken).Authorize(request)
		}
		scopes := c.acquireMergeScopes(ctx, challenge)
		token, ok := c.tokenCache().Get(ctx, c.tokenCacheKey(request, scopes...))
		if !ok {
			return nil
		}
		if token.ExpiresAt().After(time.Now()) {
			return authn.NewToken(token.Token).Authorize(request)
		}
	case authn.SchemeUnknown:
	}
	return nil
}

func (c *Client) setAuthorizationWithChallenge(ctx context.Context, request *http.Request, auth authn.AuthConfig, challenge authn.Challenge) (bool, error) {
	switch challenge.Scheme {
	case authn.SchemeBasic:
		if auth == authn.EmptyAuthConfig {
			return false, nil
		}
		username, password := auth.Username, auth.Password
		if username == "" || password == "" {
			return false, errors.New("missing username or password for basic auth")
		}
		return true, authn.NewBasic(username, password).Authorize(request)
	case authn.SchemeBearer:
		if auth.RegistryToken != "" {
			return true, authn.NewToken(auth.RegistryToken).Authorize(request)
		}
		token, err := c.acquireToken(ctx, auth, challenge)
		if err != nil {
			return false, err
		}
		scopes := c.acquireMergeScopes(ctx, challenge)
		c.tokenCache().Set(ctx, c.tokenCacheKey(request, scopes...), *token)
		return true, authn.NewToken(token.Token).Authorize(request)
	case authn.SchemeUnknown:
	}
	return false, nil
}

func (c *Client) acquireMergeScopes(ctx context.Context, challenge authn.Challenge) []string {
	requiredScopes := authn.CleanScopes(strings.Split(challenge.Parameters["scope"], " "))
	wantScopes := authn.CleanScopes(authn.GetScopes(ctx))
	// merge hinted scopes with challenged scopes
	mergeScopes := []string{}
	mergeScopes = append(mergeScopes, requiredScopes...)
	mergeScopes = append(mergeScopes, wantScopes...)
	mergeScopes = authn.CleanScopes(mergeScopes)
	return mergeScopes
}

func (c *Client) acquireToken(ctx context.Context, auth authn.AuthConfig, challenge authn.Challenge) (*authn.Token, error) {
	realm := challenge.Parameters["realm"]
	if realm == "" {
		return nil, errors.New("malformed Www-Authenticate header (missing realm)")
	}
	service := challenge.Parameters["service"]
	scopes := c.acquireMergeScopes(ctx, challenge)

	return c.fetchToken(ctx, auth, realm, service, scopes)
}

func (c *Client) fetchToken(ctx context.Context, auth authn.AuthConfig, realm string, service string, scopes []string) (*authn.Token, error) {
	if c.TokenOptions.ForceAttemptOAuth2 || auth.IdentityToken != "" {
		// fetch token with OAuth2
		token, err := c.fetchTokenWithOAuth2(ctx, auth, realm, service, scopes)
		if err != nil {
			return nil, err
		}
		if token != nil {
			return token, nil
		}
		// registry may not support OAuth2, fall back to fetch token with basic.
	}
	// fetch token with basic
	return c.fetchTokenWithBasic(ctx, auth, realm, service, scopes)
}

func (c *Client) fetchTokenWithOAuth2(ctx context.Context, auth authn.AuthConfig, realm string, service string, scopes []string) (*authn.Token, error) {
	form := stdurl.Values{}
	form.Set("client_id", c.clientID())
	if auth.IdentityToken != "" {
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", auth.IdentityToken)
	} else if auth.Username != "" && auth.Password != "" {
		form.Set("grant_type", "password")
		form.Set("username", auth.Username)
		form.Set("password", auth.Password)
		// attempt to get a refresh token
		// See: https://distribution.github.io/distribution/spec/auth/oauth/
		form.Set("access_type", "offline")
	} else {
		return nil, errors.New("no supported grant type: missing refresh token or username/password for oauth2")
	}
	if service != "" {
		form.Set("service", service)
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, realm, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client().Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(resp.Body)

	if err := xhttp.Success(resp, http.StatusNotFound); err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		// The request to the endpoint returned 404 from the POST request,
		// NOTE: Not all token servers implement oauth2, so fall back to
		// using a GET with basic auth.
		// See the Token documentation for the HTTP GET method supported
		// by all token servers in https://docs.docker.com/registry/#authentication.
		//
		//nolint:nilnil // nil token means registry unsupports OAuth2
		return nil, nil
	}

	token := &authn.Token{}
	r := io.LimitReader(resp.Body, maxAuthResponseBytes)
	if err := json.NewDecoder(r).Decode(token); err != nil {
		return nil, xhttp.MakeResponseError(resp, err)
	}
	if token.IssuedAt.IsZero() {
		token.IssuedAt = time.Now().UTC()
	}
	return token, nil
}

func (c *Client) fetchTokenWithBasic(ctx context.Context, auth authn.AuthConfig, realm string, service string, scopes []string) (*authn.Token, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, realm, http.NoBody)
	if err != nil {
		return nil, err
	}
	q := request.URL.Query()
	if service != "" {
		q.Add("service", service)
	}
	for _, scope := range scopes {
		q.Add("scope", scope)
	}
	if c.TokenOptions.OfflineToken {
		q.Add("offline_token", "true")
	}
	q.Add("client_id", c.clientID())
	request.URL.RawQuery = q.Encode()

	if auth.Username != "" && auth.Password != "" {
		request.SetBasicAuth(auth.Username, auth.Password)
	}

	resp, err := c.client().Do(request) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return nil, err
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := xhttp.Success(resp); err != nil {
		return nil, err
	}

	token := &authn.Token{}
	r := io.LimitReader(resp.Body, maxAuthResponseBytes)
	if err := json.NewDecoder(r).Decode(token); err != nil {
		return nil, xhttp.MakeResponseError(resp, err)
	}
	if token.IssuedAt.IsZero() {
		token.IssuedAt = time.Now().UTC()
	}
	return token, nil
}
