package authn_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/ocispec/authn"
)

func TestAuthConfigMarshalJSON(t *testing.T) {
	cases := []struct {
		name   string
		config authn.AuthConfig
		json   string
	}{{
		name: "auth field is calculated",
		config: authn.AuthConfig{
			Username:      "user",
			Password:      "pass",
			IdentityToken: "id",
			RegistryToken: "reg",
		},
		json: `{"username":"user","password":"pass","auth":"dXNlcjpwYXNz","identitytoken":"id","registrytoken":"reg"}`,
	}, {
		name: "auth field replaced",
		config: authn.AuthConfig{
			Username:      "user",
			Password:      "pass",
			Auth:          "blah",
			IdentityToken: "id",
			RegistryToken: "reg",
		},
		json: `{"username":"user","password":"pass","auth":"dXNlcjpwYXNz","identitytoken":"id","registrytoken":"reg"}`,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bytes, err := json.Marshal(tc.config)
			require.NoError(t, err)

			assert.Equal(t, tc.json, string(bytes))
		})
	}
}

func TestAuthConfigUnmarshalJSON(t *testing.T) {
	cases := []struct {
		name string
		json string
		err  string
		want authn.AuthConfig
	}{{
		name: "valid config no auth",
		json: `{
			"username": "user",
			"password": "pass",
			"identitytoken": "id",
			"registrytoken": "reg"
		}`,
		want: authn.AuthConfig{
			// Auth value is set based on username and password
			Auth:          "dXNlcjpwYXNz",
			Username:      "user",
			Password:      "pass",
			IdentityToken: "id",
			RegistryToken: "reg",
		},
	}, {
		name: "bad json input",
		json: `{"username":true}`,
		err:  "json: cannot unmarshal",
	}, {
		name: "auth is base64",
		json: `{ "auth": "dXNlcjpwYXNz" }`, // user:pass
		want: authn.AuthConfig{
			Username: "user",
			Password: "pass",
			Auth:     "dXNlcjpwYXNz",
		},
	}, {
		name: "auth field overrides others",
		json: `{ "auth": "dXNlcjpwYXNz", "username":"foo", "password":"bar" }`, // user:pass
		want: authn.AuthConfig{
			Username: "user",
			Password: "pass",
			Auth:     "dXNlcjpwYXNz",
		},
	}, {
		name: "auth is base64 padded",
		json: `{ "auth": "dXNlcjpwYXNzd29yZA==" }`, // user:password
		want: authn.AuthConfig{
			Username: "user",
			Password: "password",
			Auth:     "dXNlcjpwYXNzd29yZA==",
		},
	}, {
		name: "auth is not base64",
		json: `{ "auth": "bad-auth-bad" }`,
		err:  "unable to decode auth field",
	}, {
		name: "decoded auth is not valid",
		json: `{ "auth": "Zm9vYmFy" }`,
		err:  "unable to decode auth field: invalid auth, base64 as format 'username:password'",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got authn.AuthConfig
			err := json.Unmarshal([]byte(tc.json), &got)
			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tc.want, got)
		})
	}
}
