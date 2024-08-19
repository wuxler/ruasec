package name

import (
	"slices"
	"strings"

	"github.com/opencontainers/go-digest"

	"github.com/wuxler/ruasec/pkg/errdefs"
	"github.com/wuxler/ruasec/pkg/ocispec/name/internal"
)

// ValidateRegistry checks whether the Registry is valid.
func ValidateRegistry(r Registry) error {
	domain := r.Hostname()
	if !internal.AnchoredDomainRegexp.MatchString(domain) {
		return errdefs.Newf(ErrBadName, "invalid domain format %q", domain)
	}
	if err := ValidateRegistryScheme(r.Scheme()); err != nil {
		return err
	}
	return nil
}

// ValidateRegistryScheme checks whether the scheme provided is valid.
// Only "http", "https" or "" is allowed.
func ValidateRegistryScheme(scheme string) error {
	if scheme == "" {
		return nil
	}
	allowed := AllRegisteredSchemes()
	if slices.Contains(allowed, scheme) {
		return nil
	}
	return errdefs.Newf(ErrBadName, "only %s or empty scheme is allowed", strings.Join(allowed, ", "))
}

// ValidateRepository checks whether the Repository is valid.
func ValidateRepository(r Repository) error {
	if err := ValidateRegistry(r.Domain()); err != nil {
		return err
	}
	if err := ValidateRepositoryPath(r.Path()); err != nil {
		return err
	}
	return nil
}

// ValidateRepositoryPath checks whether the path provided is valid.
func ValidateRepositoryPath(path string) error {
	if !internal.AnchoredRemoteNameRegexp.MatchString(path) {
		return errdefs.Newf(ErrBadName, "invalid repository path %q, not match regexp: %s",
			path, internal.AnchoredRemoteNameRegexp)
	}
	return nil
}

// ValidateReference checks whether the reference is valid.
func ValidateReference(r Reference) error {
	if err := ValidateRepository(r.Repository()); err != nil {
		return err
	}
	if tagged, ok := r.(Tagged); ok {
		if err := ValidateTag(tagged.Tag()); err != nil {
			return err
		}
	}
	if digested, ok := r.(Digested); ok {
		if err := ValidateDigest(digested.Digest()); err != nil {
			return err
		}
	}
	return nil
}

// ValidateTag checks whether the tag is valid.
func ValidateTag(tag string) error {
	if !internal.AnchoredTagRegexp.MatchString(tag) {
		return errdefs.Newf(ErrBadName, "invalid tag format %q", tag)
	}
	return nil
}

// ValidateDigest checks whether the digest is valid.
func ValidateDigest(dgst digest.Digest) error {
	if !internal.AnchoredDigestRegexp.MatchString(dgst.String()) {
		return errdefs.Newf(ErrBadName, "invalid digest format %q", dgst)
	}
	return nil
}
