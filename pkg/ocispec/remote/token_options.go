package remote

// TokenOptions is the options for fetching token from remote.
type TokenOptions struct {
	// ClientID used in fetching OAuth2 token as a required field.
	// If empty, a default client ID is used.
	// Reference:
	// - https://docs.docker.com/registry/spec/auth/oauth/#getting-a-token
	ClientID string

	// ForceAttemptOAuth2 controls whether to follow OAuth2 with password grant
	// instead the distribution spec when authenticating using username and
	// password.
	// References:
	// - https://docs.docker.com/registry/spec/auth/jwt/
	// - https://docs.docker.com/registry/spec/auth/oauth/
	ForceAttemptOAuth2 bool

	// OfflineToken controls whether to return a refresh token along with the bearer token.
	// A refresh token is capable of getting additional bearer tokens for the same subject
	// with different scopes. The refresh token does not have an expiration and should be
	// considered completely opaque to the client.
	// References:
	// - https://docs.docker.com/registry/spec/auth/token/
	OfflineToken bool
}
