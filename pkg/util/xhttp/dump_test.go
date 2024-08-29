package xhttp_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wuxler/ruasec/pkg/util/xhttp"
)

var (
	elapsedRe    = regexp.MustCompile(`\((.*?s)\)`)
	dateHeaderRe = regexp.MustCompile(`Date: .*`)
	addressRe    = regexp.MustCompile(`127.0.0.1:\d*`)
)

func replace(t *testing.T, s string) string {
	t.Helper()
	s = elapsedRe.ReplaceAllString(s, "(<elapsed>)")
	s = dateHeaderRe.ReplaceAllString(s, "Date: <date>")
	s = addressRe.ReplaceAllString(s, "127.0.0.1:<port>")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return s
}

func TestDumpTransport_RoundTrip(t *testing.T) {
	ctx := context.Background()
	requestBody := "request body"
	responseBody := "response body"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, requestBody, string(body))
		_, err = fmt.Fprint(w, responseBody)
		require.NoError(t, err)
	}))
	defer server.Close()

	inner := http.DefaultTransport.(*http.Transport).Clone()

	testcases := []struct {
		mode xhttp.DumpMode
		want string
	}{
		{
			mode: xhttp.DumpAll,
			want: `--> POST http://127.0.0.1:<port>
POST / HTTP/1.1
Host: 127.0.0.1:<port>
User-Agent: Go-http-client/1.1
Content-Length: 12
Authorization: <redacted>
Accept-Encoding: gzip

request body

<-- POST http://127.0.0.1:<port> 200 OK (<elapsed>)
HTTP/1.1 200 OK
Content-Length: 13
Content-Type: text/plain; charset=utf-8
Date: <date>

response body

`,
		},
		{
			mode: xhttp.DumpRequest,
			want: `--> POST http://127.0.0.1:<port> [body redacted]
POST / HTTP/1.1
Host: 127.0.0.1:<port>
User-Agent: Go-http-client/1.1
Content-Length: 12
Authorization: <redacted>
Accept-Encoding: gzip

`,
		},
		{
			mode: xhttp.DumpRequest | xhttp.DumpRequestBody,
			want: `--> POST http://127.0.0.1:<port>
POST / HTTP/1.1
Host: 127.0.0.1:<port>
User-Agent: Go-http-client/1.1
Content-Length: 12
Authorization: <redacted>
Accept-Encoding: gzip

request body

`,
		},
		{
			mode: xhttp.DumpResponse,
			want: `<-- POST http://127.0.0.1:<port> 200 OK (<elapsed>) [body redacted]
HTTP/1.1 200 OK
Content-Length: 13
Content-Type: text/plain; charset=utf-8
Date: <date>

`,
		},
		{
			mode: xhttp.DumpResponse | xhttp.DumpResponseBody,
			want: `<-- POST http://127.0.0.1:<port> 200 OK (<elapsed>)
HTTP/1.1 200 OK
Content-Length: 13
Content-Type: text/plain; charset=utf-8
Date: <date>

response body

`,
		},
		{
			mode: xhttp.DumpRequest | xhttp.DumpResponse,
			want: `--> POST http://127.0.0.1:<port> [body redacted]
POST / HTTP/1.1
Host: 127.0.0.1:<port>
User-Agent: Go-http-client/1.1
Content-Length: 12
Authorization: <redacted>
Accept-Encoding: gzip

<-- POST http://127.0.0.1:<port> 200 OK (<elapsed>) [body redacted]
HTTP/1.1 200 OK
Content-Length: 13
Content-Type: text/plain; charset=utf-8
Date: <date>

`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.mode.String(), func(t *testing.T) {
			out := &bytes.Buffer{}
			tr := xhttp.NewDumpTransport(inner)
			tr.Out = out
			client := &http.Client{Transport: tr}

			ctx := xhttp.WithDumpMode(ctx, tc.mode)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, bytes.NewBufferString(requestBody))
			req.Header.Set("Authorization", "Basic <credentials>")
			require.NoError(t, err)

			_, err = client.Do(req)
			require.NoError(t, err)

			got := out.String()
			got = replace(t, got)

			assert.Equal(t, tc.want, got)
		})
	}
}
