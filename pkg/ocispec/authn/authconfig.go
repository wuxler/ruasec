package authn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	// EmptyAuthConfig represents an empty value of AuthConfig.
	EmptyAuthConfig = AuthConfig{}
)

// AuthConfig contains authorization information for connecting to a Registry
// Inlined what we use from github.com/docker/cli/cli/config/types
//
// NOTE: The value of Username and Password can be empty for accessing the registry anonymously
type AuthConfig struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// Auth is a base64 encoded string with "<username>:<password>" format which can be used
	// as value of "Authorization" http Header in a request.
	Auth string `json:"auth,omitempty"`

	// IdentityToken can be used as an refresh_token in place of username and password
	// to obtain the bearer/access token in oauth2 flow.
	// A refresh token is often referred as an identity token. If identity token is set,
	// password should not be set.
	//
	// Reference: https://docs.docker.com/registry/spec/auth/oauth/
	IdentityToken string `json:"identitytoken,omitempty"`

	// RegistryToken is a bearer token to be sent to the registry.
	//
	// Reference: https://docs.docker.com/registry/spec/auth/token/
	RegistryToken string `json:"registrytoken,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler
func (auth *AuthConfig) UnmarshalJSON(data []byte) error {
	type authConfig AuthConfig

	var shadow authConfig
	err := json.Unmarshal(data, &shadow)
	if err != nil {
		return err
	}

	*auth = AuthConfig(shadow)

	if shadow.Auth != "" {
		var derr error
		auth.Username, auth.Password, derr = DecodeAuth(shadow.Auth)
		if derr != nil {
			err = fmt.Errorf("unable to decode auth field: %w", derr)
		}
	} else if auth.Username != "" && auth.Password != "" {
		auth.Auth = EncodeAuth(auth.Username, auth.Password)
	}

	return err
}

// MarshalJSON implements json.Marshaler
func (auth AuthConfig) MarshalJSON() ([]byte, error) {
	type authConfig AuthConfig

	shadow := authConfig(auth)
	if shadow.Username != "" && shadow.Password != "" {
		shadow.Auth = EncodeAuth(shadow.Username, shadow.Password)
	}
	return json.Marshal(shadow)
}

// EncodeAuth encodes username and password as "username:password" format to
// base64 string.
func EncodeAuth(username, password string) string {
	if username == "" && password == "" {
		return ""
	}
	authStr := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(authStr))
}

// DecodeAuth decodes a base64 encoded string and returns username and password
func DecodeAuth(authStr string) (string, string, error) {
	if authStr == "" {
		return "", "", nil
	}

	decLen := base64.StdEncoding.DecodedLen(len(authStr))
	decoded := make([]byte, decLen)
	authByte := []byte(authStr)
	n, err := base64.StdEncoding.Decode(decoded, authByte)
	if err != nil {
		return "", "", err
	}
	if n > decLen {
		return "", "", errors.New("something went wrong decoding auth config")
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok || username == "" {
		return "", "", errors.New("invalid auth, base64 as format 'username:password' is required")
	}
	return username, strings.Trim(password, "\x00"), nil
}
