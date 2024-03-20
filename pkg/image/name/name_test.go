package name_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/image/name"
)

func subTestName(tName string, good bool, notes ...string) string {
	if tName == "" {
		tName = "empty"
	}
	if len(notes) > 0 {
		tName = strings.Join(notes, " ") + " " + tName
	}
	if good {
		tName = "(good) " + tName
	} else {
		tName = "(bad) " + tName
	}
	return tName
}

func TestNewRegistry(t *testing.T) {
	testcases := []struct {
		input   string
		host    string
		scheme  string
		wantErr bool
	}{
		{
			input: "example.registry.com",
			host:  "example.registry.com",
		},
		{
			input: "example.registry.com:8080",
			host:  "example.registry.com:8080",
		},
		{
			input: "example.registry.com:8080/library/hello",
			host:  "example.registry.com:8080",
		},
		{
			input: "example.registry.com:8080/library/hello:latest",
			host:  "example.registry.com:8080",
		},
		{
			input:  "http://example.registry.com:8080", // http scheme
			host:   "example.registry.com:8080",
			scheme: "http",
		},
		{
			input:  "https://example.registry.com:8080", // https scheme
			host:   "example.registry.com:8080",
			scheme: "https",
		},
		{
			input:   "wss://example.registry.com:8080", // unsupported scheme
			wantErr: true,
		},
		{
			input:  "localhost",
			host:   "localhost",
			scheme: "http",
		},
		{
			input:  "localhost:3000", // localhost:port
			host:   "localhost:3000",
			scheme: "http",
		},
		{
			input:  "172.16.18.130", // ipv4
			host:   "172.16.18.130",
			scheme: "http",
		},
		{
			input:  "172.16.18.130:3000", // ipv4:port
			host:   "172.16.18.130:3000",
			scheme: "http",
		},
		{
			input: "[fd00:1:2::3]:75050", // ipv6 compressed
			host:  "[fd00:1:2::3]:75050",
		},
		{
			input: "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:75050", // ipv6 long format
			host:  "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:75050",
		},
	}

	for _, tc := range testcases {
		testname := subTestName(tc.input, tc.wantErr)
		t.Run(testname, func(t *testing.T) {
			got, err := name.NewRegistry(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.host, got.Hostname())
			assert.Equal(t, tc.scheme, got.Scheme())
		})
	}
}

func TestNewRegistry_Normalize(t *testing.T) {
	testcases := []struct {
		name    string
		input   string
		host    string
		scheme  string
		wantErr bool
	}{
		{
			name: "(good) empty",
			host: name.DefaultRegistry,
		},
		{
			name:  "(good) rewrite docker.io",
			input: "docker.io",
			host:  name.DefaultRegistry,
		},
		{
			name:  "(good) rewrite index.docker.io",
			input: "index.docker.io",
			host:  name.DefaultRegistry,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := name.NewRegistry(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.host, got.Hostname())
			assert.Equal(t, tc.scheme, got.Scheme())
		})
	}
}

func TestNewRepository(t *testing.T) {
	type testcase struct {
		input   string
		host    string
		scheme  string
		path    string
		wantErr bool
	}
	testcases := []testcase{
		{
			input: "registry.example.com/hello",
			host:  "registry.example.com",
			path:  "hello",
		},
		{
			input: "registry.example.com/hello/world",
			host:  "registry.example.com",
			path:  "hello/world",
		},
		{
			input:  "127.0.0.1:5000/hello/world",
			host:   "127.0.0.1:5000",
			scheme: "http",
			path:   "hello/world",
		},
		{
			input:  "127.0.0.1:5000/hello",
			host:   "127.0.0.1:5000",
			scheme: "http",
			path:   "hello",
		},
		{
			input:  "http://registry.example.com/hello/world",
			host:   "registry.example.com",
			scheme: "http",
			path:   "hello/world",
		},
		{
			input:  "https://registry.example.com/hello/world",
			host:   "registry.example.com",
			scheme: "https",
			path:   "hello/world",
		},
		{
			input:  "http://registry.example.com/hello/world:latest",
			host:   "registry.example.com",
			scheme: "http",
			path:   "hello/world",
		},
		{
			input:  "https://registry.example.com/hello/world:latest",
			host:   "registry.example.com",
			scheme: "https",
			path:   "hello/world",
		},
		{
			// This test case was moved from invalid to valid since it is valid input
			// when specified with a hostname, it removes the ambiguity from about
			// whether the value is an identifier or repository name
			input: "docker.io/1a3f5e7d9c1b3a5f7e9d1c3b5a7f9e1d3c5b7a9f1e3d5d7c9b1a3f5e7d9c1b3a",
			host:  name.DefaultRegistry,
			path:  "library/1a3f5e7d9c1b3a5f7e9d1c3b5a7f9e1d3c5b7a9f1e3d5d7c9b1a3f5e7d9c1b3a",
		},
	}

	invalids := []string{
		"hello/World",
		"-hello",
		"-hello/world",
		"-registry.example.com/hello/world",
		"hello///world",
		"registry.example.com/hello/World",
		"registry.example.com/hello///world",
		"1a3f5e7d9c1b3a5f7e9d1c3b5a7f9e1d3c5b7a9f1e3d5d7c9b1a3f5e7d9c1b3a",
		"hello/world/",
	}

	for _, invalid := range invalids {
		testcases = append(testcases, testcase{input: invalid, wantErr: true})
	}
	for _, tc := range testcases {
		testname := subTestName(tc.input, !tc.wantErr)
		t.Run(testname, func(t *testing.T) {
			got, err := name.NewRepository(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.host, got.Domain().Hostname())
			assert.Equal(t, tc.scheme, got.Domain().Scheme())
			assert.Equal(t, tc.path, got.Path())
		})
	}
}

func TestNewRepository_Normalize(t *testing.T) {
	type testcase struct {
		input   string
		host    string
		scheme  string
		path    string
		wantErr bool
	}
	testcases := []testcase{
		{
			input: "hello",
			host:  name.DefaultRegistry,
			path:  "library/hello",
		},
		{
			input: "registry.example.com/hello/world",
			host:  "registry.example.com",
			path:  "hello/world",
		},
		{
			input: "docker.io/hello",
			host:  name.DefaultRegistry,
			path:  "library/hello",
		},
		{
			input: "docker.io/hello/world",
			host:  name.DefaultRegistry,
			path:  "hello/world",
		},
		{
			input: "index.docker.io/hello/world",
			host:  name.DefaultRegistry,
			path:  "hello/world",
		},
		{
			input: "registry-1.docker.io/hello/world",
			host:  name.DefaultRegistry,
			path:  "hello/world",
		},
	}

	for _, tc := range testcases {
		testname := subTestName(tc.input, !tc.wantErr)
		t.Run(testname, func(t *testing.T) {
			got, err := name.NewRepository(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.host, got.Domain().Hostname())
			assert.Equal(t, tc.scheme, got.Domain().Scheme())
			assert.Equal(t, tc.path, got.Path())
		})
	}
}

func TestNewReference(t *testing.T) {
	type testcase struct {
		input        string
		host         string
		scheme       string
		path         string
		tag          string
		digest       digest.Digest
		noDefaultTag bool
		wantErr      bool
	}
	testcases := []testcase{
		{
			input:   "registry.example.com",
			wantErr: true,
		},
		{
			input: "registry.example.com/hello",
			host:  "registry.example.com",
			path:  "hello",
			tag:   "latest",
		},
		{
			input:  "https://registry.example.com/hello:tag",
			host:   "registry.example.com",
			scheme: "https",
			path:   "hello",
			tag:    "tag",
		},
		{
			input: "registry.example.com/hello:tag",
			host:  "registry.example.com",
			path:  "hello",
			tag:   "tag",
		},
		{
			input: "registry.example.com:5000/hello:tag",
			host:  "registry.example.com:5000",
			path:  "hello",
			tag:   "tag",
		},
		{
			input:  "registry.example.com:5000/hello@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			host:   "registry.example.com:5000",
			path:   "hello",
			digest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",

			noDefaultTag: true,
		},
		{
			input:  "registry.example.com:5000/hello:tag@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			host:   "registry.example.com:5000",
			path:   "hello",
			tag:    "tag",
			digest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
		{
			input:   "",
			wantErr: true,
		},
		{
			input:   ":justtag",
			wantErr: true,
		},
		{
			input:   "@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			wantErr: true,
		},
		{
			input:   "repo@sha256:ffffffffffffffffffffffffffffffffff",
			wantErr: true,
		},
		{
			input:   "validname@invaliddigest:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			wantErr: true,
		},
		{
			input:   "Uppercase:tag",
			wantErr: true,
		},
		{
			input:   "Uppercase/lowercase:tag",
			wantErr: true,
		},
		{
			input:   "test:5000/Uppercase/lowercase:tag",
			wantErr: true,
		},
		{
			input: "lowercase:Uppercase",
			host:  name.DefaultRegistry,
			path:  "library/lowercase",
			tag:   "Uppercase",
		},
		{
			input:   strings.Repeat("a/", 128) + "a:tag",
			wantErr: true,
		},
		{
			input:   "aa/asdf$$^/aa",
			wantErr: true,
		},
		{
			input:        "hello",
			noDefaultTag: true,
			wantErr:      true,
		},
	}

	for _, tc := range testcases {
		testname := subTestName(tc.input, !tc.wantErr)
		t.Run(testname, func(t *testing.T) {
			opts := []name.Option{}
			if tc.noDefaultTag {
				opts = append(opts, name.WithDefaultTag(""))
			}
			got, err := name.NewReference(tc.input, opts...)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.host, got.Repository().Domain().Hostname())
			assert.Equal(t, tc.scheme, got.Repository().Domain().Scheme())
			assert.Equal(t, tc.path, got.Repository().Path())
			if tc.tag != "" {
				tagged, ok := got.(name.Tagged)
				require.True(t, ok)
				assert.Equal(t, tc.tag, tagged.Tag())
			}
			if tc.digest != "" {
				digested, ok := got.(name.Digested)
				require.True(t, ok)
				assert.Equal(t, tc.digest, digested.Digest())
			}
		})
	}
}

func TestWithTag(t *testing.T) {
	type testcase struct {
		repo    string
		tag     string
		want    string
		wantErr bool
	}
	testcases := []testcase{
		{
			repo: "hello",
			tag:  "v1",
			want: fmt.Sprintf("%s/%s/hello:v1", name.DefaultRegistry, name.DefaultNamespace),
		},
		{
			repo: "hello/world",
			tag:  "v1",
			want: fmt.Sprintf("%s/hello/world:v1", name.DefaultRegistry),
		},
		{
			repo: "example.com/hello/world",
			tag:  "v1",
			want: "example.com/hello/world:v1",
		},
		{
			repo: "http://example.com/hello/world",
			tag:  "v1",
			want: "example.com/hello/world:v1",
		},
		{
			repo:    "hello",
			tag:     "",
			wantErr: true,
		},
		{
			repo:    "hello",
			tag:     "@abc",
			wantErr: true,
		},
		{
			repo:    "hello",
			tag:     "a/b/c",
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		testname := subTestName(tc.repo+"_"+tc.tag, !tc.wantErr)
		t.Run(testname, func(t *testing.T) {
			repo, err := name.NewRepository(tc.repo)
			require.NoError(t, err)
			got, err := name.WithTag(repo, tc.tag)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.String())
		})
	}
}

func TestWithDigest(t *testing.T) {
	type testcase struct {
		repo    string
		digest  digest.Digest
		want    string
		wantErr bool
	}
	testcases := []testcase{
		{
			repo:   "example.com/hello/world",
			digest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			want:   "example.com/hello/world@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
		{
			repo:    "example.com/hello/world",
			digest:  "invalid-digest",
			wantErr: true,
		},
	}
	for _, tc := range testcases {
		testname := subTestName(tc.repo+"_"+tc.digest.String(), !tc.wantErr)
		t.Run(testname, func(t *testing.T) {
			repo, err := name.NewRepository(tc.repo)
			require.NoError(t, err)
			got, err := name.WithDigest(repo, tc.digest)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.String())
		})
	}
}

func TestWithPath(t *testing.T) {
	type testcase struct {
		registry string
		path     string
		want     string
		wantErr  bool
	}
	testcases := []testcase{
		{
			registry: "example.com",
			path:     "a/b/c",
			want:     "example.com/a/b/c",
		},
		{
			registry: "example.com",
			path:     "a/b@c",
			wantErr:  true,
		},
	}
	for _, tc := range testcases {
		testname := subTestName(tc.registry+"_"+tc.path, !tc.wantErr)
		t.Run(testname, func(t *testing.T) {
			r, err := name.NewRegistry(tc.registry)
			require.NoError(t, err)
			got, err := name.WithPath(r, tc.path)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.String())
		})
	}
}
