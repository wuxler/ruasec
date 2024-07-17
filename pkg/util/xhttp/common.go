package xhttp

import (
	"fmt"
	stdurl "net/url"
	"strings"

	"github.com/spf13/cast"
)

// ParseHostScheme parses any address string and return host, scheme and error.
// If addr is a host/domain style string, the returned scheme will be "".
func ParseHostScheme(addr string) (string, string, error) {
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

// RangeString formats a pair of start and end offsets in the "Content-Range" form.
// The input start is inclusive and the end exclusive, to match Go convention,
// whereas Content-Range is inclusive on both ends.
func RangeString(start, end int64) string {
	end--
	if end < 0 {
		end = 0
	}
	return fmt.Sprintf("%d-%d", start, end)
}

// ParseRange extracts the start and end offsets from a Content-Range string.
// The resulting start is inclusive and the end exclusive, to match Go convention,
// whereas Content-Range is inclusive on both ends.
func ParseRange(s string) (start, end int64, ok bool) {
	s0, s1, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, false
	}
	p0, err0 := cast.ToInt64E(s0)
	p1, err1 := cast.ToInt64E(s1)
	if p1 > 0 {
		p1++
	}
	return p0, p1, err0 == nil && err1 == nil
}
