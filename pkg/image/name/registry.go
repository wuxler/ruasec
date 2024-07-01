package name

import (
	"fmt"
	"net"
	stdurl "net/url"
	"regexp"
	"strings"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/image/name/internal"
	"github.com/wuxler/ruasec/pkg/image/name/internal/xregexp"
)

var (
	defaultRegistryAliases = map[string][]string{
		DefaultRegistry: {
			DockerIOHostname,
			DockerIndexHostname,
		},
	}

	// detect the loopback IP (127.0.0.1)
	reLoopback = regexp.MustCompile(regexp.QuoteMeta("127.0.0.1"))

	// detect the loopback IPV6 (::1)
	reipv6Loopback = regexp.MustCompile(regexp.QuoteMeta("::1"))
)

type registry struct {
	scheme   string
	hostname string
}

func (r registry) String() string {
	return r.hostname
}

// Scheme returns the scheme ("http" or "https") of the registry. The
// scheme may including by the raw domain string, or guessed by the
// hostname such as "localhost" represents to "http", or set by user.
// Otherwise it will return empty string "".
func (r registry) Scheme() string {
	return r.scheme
}

// Hostname returns the hostname of the registry. A hostname can be
// formatted as a domain-name, IPv4 address, or IPv6 address. More to
// see RFC3986 appendix-A.
func (r registry) Hostname() string {
	return r.hostname
}

// WithScheme returns a copy of Registry and overwrites the scheme
// of the Registry.
func (r registry) WithScheme(scheme string) Registry {
	clone := r
	clone.scheme = scheme
	return clone
}

func newRegistry(name string, opts options) (registry, error) {
	var zero registry
	r, err := parseRegistry(name, opts)
	if err != nil {
		return zero, fmt.Errorf("unable to parse registry %q: %w", name, err)
	}
	normalized := normalizeRegistry(r, opts)
	if err := ValidateRegistry(normalized); err != nil {
		return zero, fmt.Errorf("invalid registry %q: %w", name, err)
	}
	return normalized, nil
}

func normalizeRegistry(r registry, opts options) registry {
	if r.hostname == "" {
		r.hostname = opts.defaultRegistry
	}
	if redirect, ok := isDockerLegacyDomain(r.hostname); ok {
		// rewrite "docker.io" and "index.docker.io" to "registry-1.docker.io"
		// See: https://github.com/google/go-containerregistry/issues/68
		r.hostname = redirect
	}
	if r.scheme == "" {
		r.scheme = guessHTTP(r.hostname)
	}
	return r
}

func parseRegistry(name string, opts options) (registry, error) {
	var zero registry
	if name == "" {
		if opts.strict {
			return zero, errdefs.Newf(ErrBadName, "strict validation requires the registry to be explicitly defined")
		}
		return zero, nil
	}

	// split "http(s)://<host>" to "http(s)" and "<host>"
	scheme, _ := splitAndTrimScheme(name)
	if scheme != "" {
		url, err := stdurl.Parse(name)
		if err != nil {
			return zero, errdefs.Newf(ErrBadName, "unable to parse as url: %w", err)
		}
		return registry{scheme: url.Scheme, hostname: url.Host}, nil
	}

	// Per RFC 3986, registries (authorities) are required to be prefixed with "//"
	// url.Host == hostname[:port] == authority
	if url, err := stdurl.Parse("dummy://" + name); err == nil {
		return registry{hostname: url.Host}, nil
	}

	return zero, errdefs.Newf(ErrBadName, "registry must be a valid RFC 3986 URI authority")
}

func guessHTTP(hostname string) string {
	if hostname == "" {
		return ""
	}
	if isRFC1918(hostname) || isLocalhost(hostname) {
		return "http"
	}
	return ""
}

// isRFC1918 detect whether the hostname is private ip address.
func isRFC1918(hostname string) bool {
	s := strings.Split(hostname, ":")[0]
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if _, block, err := net.ParseCIDR(cidr); err == nil {
			if block.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// isLocalhost detect whether the hostname is a loopback address.
func isLocalhost(hostname string) bool {
	return strings.HasPrefix(hostname, "localhost") ||
		reLoopback.MatchString(hostname) ||
		reipv6Loopback.MatchString(hostname)
}

// isDockerLegacyDomain detect whether the hostname is the docker legacy
// default domain.
func isDockerLegacyDomain(hostname string) (string, bool) {
	for redirect, aliases := range defaultRegistryAliases {
		for _, alias := range aliases {
			if hostname == alias {
				return redirect, true
			}
		}
	}
	return hostname, false
}

// splitAndTrimScheme splits scheme prefix, returns scheme and trimmed name.
func splitAndTrimScheme(name string) (scheme, remainder string) {
	matches, _ := xregexp.SubmatchCaptures(internal.AnchoredSchemePrefixRegexp, name)
	if prefix, ok := matches["prefix"]; ok {
		scheme = strings.TrimSuffix(prefix, "://")
		remainder = strings.TrimPrefix(name, prefix)
	} else {
		remainder = name
	}
	return
}
