package name

import (
	"fmt"
	"strings"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec/name/internal"
)

type repository struct {
	domain Registry
	// path is the remote name without registry doamin.
	path string
}

func (r repository) String() string {
	if r.domain.String() == "" {
		return r.path
	}
	return fmt.Sprintf("%s/%s", r.domain, r.path)
}

// Domain returns the domain component as a Registry object.
func (r repository) Domain() Registry {
	return r.domain
}

// Path returns the path (or "remote-name") component.
func (r repository) Path() string {
	return r.path
}

func newRepository(name string, opts options) (repository, error) {
	var zero repository
	r, err := parseRepository(name, opts)
	if err != nil {
		return zero, fmt.Errorf("unable to parse repository %q: %w", name, err)
	}
	normalized := normalizeRepository(r, opts)
	if err := ValidateRepository(normalized); err != nil {
		return zero, fmt.Errorf("invalid repository %q: %w", name, err)
	}
	return normalized, nil
}

func normalizeRepository(repo repository, _ options) repository {
	if hasImpliciyNamespace(repo.domain.Hostname(), repo.path) {
		repo.path = DefaultNamespace + "/" + repo.path
	}
	return repo
}

func parseRepository(name string, opts options) (repository, error) {
	var zero repository
	if name == "" {
		return zero, errdefs.Newf(ErrBadName, "non-empty repository name is required")
	}

	if ok := internal.AnchoredIdentifierRegexp.MatchString(name); ok {
		return zero, errdefs.Newf(ErrBadName, "invalid format: repository name cannot be 64-byte hexadecimal strings")
	}

	// split "http(s)://<host>/<path>" to "http(s)" and "<host>/<path>
	scheme, name := SplitScheme(name)

	// check if it is repository name only
	var domain string
	var remainder string
	if i := strings.IndexRune(name, '/'); i == -1 {
		if strings.ContainsAny(name, ".:") {
			domain = name
		} else {
			remainder = name
		}
	} else if !strings.ContainsAny(name[:i], ".:") && name[:i] != "localhost" {
		remainder = name
	} else {
		domain, remainder = name[:i], name[i+1:]
	}
	registryAddress := domain
	if scheme != "" {
		registryAddress = scheme + "://" + registryAddress
	}
	registry, err := newRegistry(registryAddress, opts)
	if err != nil {
		return zero, fmt.Errorf("invalid registry address: %s: %w", registryAddress, err)
	}

	// check if it is tagged path
	remoteName := remainder
	if i := strings.IndexRune(remoteName, ':'); i > -1 {
		remoteName = remoteName[:i]
	}
	if remoteName == "" {
		return zero, errdefs.Newf(ErrBadName, "repository name is empty")
	}
	if strings.ToLower(remoteName) != remoteName {
		return zero, errdefs.Newf(ErrBadName, "repository name must be lowercase")
	}
	if hasImpliciyNamespace(registry.Hostname(), remoteName) && opts.strict {
		return zero, errdefs.Newf(ErrBadName, "strict validation requires the full repository path (missing 'library')")
	}

	repo := repository{
		domain: registry,
		path:   remoteName,
	}
	return repo, nil
}

func hasImpliciyNamespace(hostname string, repo string) bool {
	_, legacy := isDockerLegacyDomain(hostname)
	return !strings.ContainsRune(repo, '/') && (legacy || hostname == DefaultRegistry)
}
