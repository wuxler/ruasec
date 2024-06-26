package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	stdurl "net/url"
	"strings"
	"time"

	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
	"github.com/wuxler/ruasec/pkg/util/xio"
	"github.com/wuxler/ruasec/pkg/xlog"
)

const (
	// 300ms is the default fallback period for go's DNS dialer but we could make this configurable.
	fallbackDelay = 300 * time.Millisecond
)

type pinger interface {
	fmt.Stringer
	Ping(ctx context.Context) (bool, error)
}

// pingParallel do ping request in parallel.
//
// See:
//   - https://github.com/google/go-containerregistry/pull/1521
//   - [net/dial.go]
//
// [net/dial.go]: https://cs.opensource.google/go/go/+/master:src/net/dial.go;l=447;drc=38cfb3be9d486833456276777155980d1ec0823e
//
//nolint:gocognit // known complexity
func pingParallel(ctx context.Context, primary, fallback pinger) (bool, error) {
	if fallback == nil {
		result, err := primary.Ping(ctx)
		return result, err
	}
	returned := make(chan struct{})
	defer close(returned)

	type pingResult struct {
		resp bool
		error
		primary bool
		done    bool
	}
	results := make(chan pingResult) // unbuffered

	startRacer := func(ctx context.Context, isPrimary bool) {
		p := primary
		if !isPrimary {
			p = fallback
		}
		success, err := p.Ping(ctx)
		select {
		case results <- pingResult{resp: success, error: err, primary: isPrimary, done: true}:
		case <-returned:
			if success {
				xlog.C(ctx).Debugf("%s lost race", p)
			}
		}
	}

	// start the main racer
	primaryCtx, primaryCancel := context.WithCancel(ctx)
	defer primaryCancel()
	go startRacer(primaryCtx, true)

	// start the timer for the fallback racer
	fallbackTimer := time.NewTimer(fallbackDelay)
	defer fallbackTimer.Stop()

	var primaryResult, fallbackResult pingResult
	for {
		select {
		case <-fallbackTimer.C:
			fallbackCtx, fallbackCancel := context.WithCancel(ctx)
			defer fallbackCancel() //nolint:gocritic // only call once when fallbackTimer fires
			go startRacer(fallbackCtx, false)

		case res := <-results:
			if res.error == nil {
				return res.primary, nil
			}
			if res.primary {
				primaryResult = res
			} else {
				fallbackResult = res
			}
			if primaryResult.done && fallbackResult.done {
				return false, errors.Join(primaryResult.error, fallbackResult.error)
			}
			if res.primary && fallbackTimer.Stop() {
				// If we were able to stop the timer, that means it was running (hadn't yet
				// started the fallback), but we just got an error on the primary path, so
				// start the fallback immediately (in 0 nanoseconds).
				fallbackTimer.Reset(0)
			}
		}
	}
}

// parseHostScheme parse any address string and return host, scheme and error.
// If addr is a host/domain style string, the returned scheme will be "".
func parseHostScheme(addr string) (string, string, error) {
	if strings.Contains(addr, "://") {
		url, err := stdurl.Parse(addr)
		if err != nil {
			return "", "", err
		}
		return url.Host, url.Scheme, nil
	}

	url, err := stdurl.Parse("https://" + addr)
	if err != nil {
		return "", "", err
	}
	return url.Host, "", nil
}

type schemePinger struct {
	client *http.Client
	host   string
	scheme string
}

func (p *schemePinger) String() string {
	return fmt.Sprintf("GET %s://%s/v2/", p.scheme, p.host)
}

func (p *schemePinger) Ping(ctx context.Context) (bool, error) {
	url := fmt.Sprintf("%s://%s/v2/", p.scheme, p.host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, err
	}
	resp, err := p.client.Do(req) //nolint:bodyclose // closed by xio.CloseAndSkipError
	if err != nil {
		return false, fmt.Errorf("failed to do request to %s %s: %w", req.Method, req.URL, err)
	}
	defer xio.CloseAndSkipError(resp.Body)
	if err := distribution.HTTPSuccess(resp, http.StatusUnauthorized); err != nil {
		return false, err
	}
	return true, nil
}
