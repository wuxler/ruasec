package authn_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/wuxler/ruasec/pkg/ocispec/authn"
)

func Test_ParseChallenge(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   authn.Challenge
	}{
		{
			name: "empty header",
			want: authn.Challenge{Scheme: authn.SchemeUnknown},
		},
		{
			name:   "unknown scheme",
			header: "foo bar",
			want:   authn.Challenge{Scheme: authn.SchemeUnknown},
		},
		{
			name:   "basic challenge",
			header: `Basic realm="Test Registry"`,
			want:   authn.Challenge{Scheme: authn.SchemeBasic},
		},
		{
			name:   "basic challenge with no parameters",
			header: "Basic",
			want:   authn.Challenge{Scheme: authn.SchemeBasic},
		},
		{
			name:   "basic challenge with no parameters but spaces",
			header: "Basic  ",
			want:   authn.Challenge{Scheme: authn.SchemeBasic},
		},
		{
			name:   "bearer challenge",
			header: `Bearer realm="https://auth.example.io/token",service="registry.example.io",scope="repository:library/hello-world:pull,push"`,
			want: authn.Challenge{
				Scheme: authn.SchemeBearer,
				Parameters: map[string]string{
					"realm":   "https://auth.example.io/token",
					"service": "registry.example.io",
					"scope":   "repository:library/hello-world:pull,push",
				},
			},
		},
		{
			name:   "bearer challenge with multiple scopes",
			header: `Bearer realm="https://auth.example.io/token",service="registry.example.io",scope="repository:library/alpine:pull,push repository:ubuntu:pull"`,
			want: authn.Challenge{
				Scheme: authn.SchemeBearer,
				Parameters: map[string]string{
					"realm":   "https://auth.example.io/token",
					"service": "registry.example.io",
					"scope":   "repository:library/alpine:pull,push repository:ubuntu:pull",
				}},
		},
		{
			name:   "bearer challenge with no parameters",
			header: "Bearer",
			want:   authn.Challenge{Scheme: authn.SchemeBearer},
		},
		{
			name:   "bearer challenge with no parameters but spaces",
			header: "Bearer  ",
			want:   authn.Challenge{Scheme: authn.SchemeBearer},
		},
		{
			name:   "bearer challenge with white spaces",
			header: `Bearer realm = "https://auth.example.io/token"   ,service=registry.example.io, scope  ="repository:library/hello-world:pull,push"  `,
			want: authn.Challenge{
				Scheme: authn.SchemeBearer,
				Parameters: map[string]string{
					"realm":   "https://auth.example.io/token",
					"service": "registry.example.io",
					"scope":   "repository:library/hello-world:pull,push",
				},
			},
		},
		{
			name:   "bad bearer challenge (incomplete parameter with spaces)",
			header: `Bearer realm="https://auth.example.io/token",service`,
			want: authn.Challenge{
				Scheme: authn.SchemeBearer,
				Parameters: map[string]string{
					"realm": "https://auth.example.io/token",
				},
			},
		},
		{
			name:   "bad bearer challenge (incomplete parameter with no value)",
			header: `Bearer realm="https://auth.example.io/token",service=`,
			want: authn.Challenge{
				Scheme: authn.SchemeBearer,
				Parameters: map[string]string{
					"realm": "https://auth.example.io/token",
				},
			},
		},
		{
			name:   "bad bearer challenge (incomplete parameter with spaces)",
			header: `Bearer realm="https://auth.example.io/token",service= `,
			want: authn.Challenge{
				Scheme: authn.SchemeBearer,
				Parameters: map[string]string{
					"realm": "https://auth.example.io/token",
				},
			},
		},
		{
			name:   "bad bearer challenge (incomplete quote)",
			header: `Bearer realm="https://auth.example.io/token",service="registry`,
			want: authn.Challenge{
				Scheme: authn.SchemeBearer,
				Parameters: map[string]string{
					"realm": "https://auth.example.io/token",
				},
			},
		},
		{
			name:   "bearer challenge with empty parameter value",
			header: `Bearer realm="https://auth.example.io/token",empty="",service="registry.example.io",scope="repository:library/hello-world:pull,push"`,
			want: authn.Challenge{
				Scheme: authn.SchemeBearer,
				Parameters: map[string]string{
					"realm":   "https://auth.example.io/token",
					"empty":   "",
					"service": "registry.example.io",
					"scope":   "repository:library/hello-world:pull,push",
				},
			},
		},
		{
			name:   "bearer challenge with escaping parameter value",
			header: `Bearer foo="foo\"bar",hello="\"hello world\""`,
			want: authn.Challenge{
				Scheme: authn.SchemeBearer,
				Parameters: map[string]string{
					"foo":   `foo"bar`,
					"hello": `"hello world"`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authn.ParseChallenge(tt.header)
			assert.Equal(t, tt.want, got)
		})
	}
}
