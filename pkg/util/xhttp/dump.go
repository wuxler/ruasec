package xhttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/wuxler/ruasec/pkg/util/xcontext"
	"github.com/wuxler/ruasec/pkg/xlog"
)

// WithDumpMode adds a dump mode to the context.
func WithDumpMode(ctx context.Context, mode DumpMode) context.Context {
	return xcontext.WithValue(ctx, mode)
}

// GetDumpMode returns the dump mode from the context.
func GetDumpMode(ctx context.Context) (DumpMode, bool) {
	return xcontext.GetValue[DumpMode](ctx)
}

// DisableDumpMode disables the dump mode and re-adds to the context.
func DisableDumpMode(ctx context.Context, modes ...DumpMode) context.Context {
	mode, ok := GetDumpMode(ctx)
	if !ok {
		return ctx
	}
	return WithDumpMode(ctx, mode.Disable(modes...))
}

// DumpMode is a bitmask for dumping requests and responses control.
type DumpMode uint64

const (
	DumpRequest DumpMode = 1 << (64 - 1 - iota)
	DumpRequestBody
	DumpResponse
	DumpResponseBody
)

const (
	DumpAll = DumpRequest | DumpRequestBody | DumpResponse | DumpResponseBody
)

func (m DumpMode) String() string {
	ss := []string{}
	if m.IsDumpRequest() {
		ss = append(ss, "DumpRequest")
	}
	if m.IsDumpRequestBody() {
		ss = append(ss, "DumpRequestBody")
	}
	if m.IsDumpResponse() {
		ss = append(ss, "DumpResponse")
	}
	if m.IsDumpResponseBody() {
		ss = append(ss, "DumpResponseBody")
	}
	if len(ss) == 0 {
		return "DumpNone"
	}
	return strings.Join(ss, "|")
}

func (m DumpMode) IsEnable() bool {
	return m != 0
}

func (m DumpMode) IsDumpRequest() bool {
	return m&DumpRequest != 0
}

func (m DumpMode) IsDumpRequestBody() bool {
	return m&DumpRequestBody != 0
}

func (m DumpMode) IsDumpResponse() bool {
	return m&DumpResponse != 0
}

func (m DumpMode) IsDumpResponseBody() bool {
	return m&DumpResponseBody != 0
}

func (m *DumpMode) DisableAll() DumpMode {
	*m = 0
	return *m
}

func (m *DumpMode) Disable(modes ...DumpMode) DumpMode {
	for _, mode := range modes {
		*m &^= mode
	}
	return *m
}

func (m *DumpMode) Enable(modes ...DumpMode) DumpMode {
	for _, mode := range modes {
		*m |= mode
	}
	return *m
}

// Inspired by: github.com/motemen/go-loghttp

var _ http.RoundTripper = (*DumpTransport)(nil)

// NewDumpTransport returns a new [DumpTransport] with the given inner transport.
func NewDumpTransport(inner http.RoundTripper) *DumpTransport {
	return &DumpTransport{
		Out:         os.Stdout,
		DefaultMode: DumpAll,
		inner:       inner,
	}
}

// DumpTransport is a implementation of [http.RoundTripper] that dumps requests and responses.
type DumpTransport struct {
	Out         io.Writer
	DefaultMode DumpMode

	inner http.RoundTripper
}

func (m *DumpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	mode := m.DefaultMode
	if value, ok := GetDumpMode(req.Context()); ok {
		mode &= value // merge dump mode
	}

	if !mode.IsEnable() {
		return m.inner.RoundTrip(req)
	}

	buf := &bytes.Buffer{}
	defer func() {
		if _, err := io.Copy(m.writer(), buf); err != nil {
			xlog.FromContext(req.Context()).Warnf("failed to dump request/response: %v", err)
		}
	}()

	if mode.IsDumpRequest() {
		m.dumpRequest(req, mode, buf)
	}

	start := time.Now()
	resp, err := m.inner.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	if mode.IsDumpResponse() {
		elapsed := time.Since(start)
		m.dumpResponse(resp, mode, elapsed, buf)
	}
	return resp, err
}

func (m *DumpTransport) writer() io.Writer {
	if m.Out != nil {
		return m.Out
	}
	return os.Stdout
}

func (m *DumpTransport) dumpRequest(req *http.Request, mode DumpMode, w io.Writer) {
	// write title line
	title := fmt.Sprintf("--> %s %s", req.Method, req.URL)
	if !mode.IsDumpRequestBody() {
		title += " [body redacted]"
	}
	_, _ = fmt.Fprintf(w, "%s\n", title)

	// save these headers so we can redact Authorization
	headers := req.Header.Clone()
	if req.Header != nil && req.Header.Get("authorization") != "" {
		req.Header.Set("authorization", "<redacted>")
	}

	// dump request
	b, err := httputil.DumpRequestOut(req, mode.IsDumpRequestBody())
	if bytes.HasSuffix(b, []byte("\r\n\r\n")) {
		b = b[:len(b)-4]
	}
	if err != nil {
		_, _ = fmt.Fprintf(w, "failed to dump request: %v\n", err)
	} else {
		_, _ = fmt.Fprintf(w, "%s\n", string(b))
	}

	// restore the non-redacted headers
	req.Header = headers

	_, _ = fmt.Fprint(w, "\n")
}

func (m *DumpTransport) dumpResponse(resp *http.Response, mode DumpMode, elapsed time.Duration, w io.Writer) {
	req := resp.Request

	// write title line
	title := fmt.Sprintf("<-- %s %s %d %s", req.Method, req.URL, resp.StatusCode, http.StatusText(resp.StatusCode))
	if elapsed > 0 {
		title += fmt.Sprintf(" (%s)", elapsed)
	}
	if !mode.IsDumpResponseBody() {
		title += " [body redacted]"
	}
	_, _ = fmt.Fprintf(w, "%s\n", title)

	// dump response
	b, err := httputil.DumpResponse(resp, mode.IsDumpResponseBody())
	if bytes.HasSuffix(b, []byte("\r\n\r\n")) {
		b = b[:len(b)-4]
	}
	if err != nil {
		_, _ = fmt.Fprintf(w, "failed to dump response: %v\n", err)
	} else {
		_, _ = fmt.Fprintf(w, "%s\n", string(b))
	}

	_, _ = fmt.Fprint(w, "\n")
}
