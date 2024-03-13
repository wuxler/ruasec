package internal

import (
	"regexp"

	"github.com/wuxler/ruasec/pkg/image/name/internal/xregexp"
)

var (
	// re compiles the string to a regular expression.
	re         = regexp.MustCompile
	literal    = xregexp.Literal
	expression = xregexp.Expression
	optional   = xregexp.Optional
	repeated   = xregexp.Repeated
	group      = xregexp.Group
	capture    = xregexp.Capture
	anchored   = xregexp.Anchored
)

var (
	// DigestRegexp matches well-formed digests, including algorithm (e.g. "sha256:<encoded>").
	DigestRegexp = re(digestPat)

	// AnchoredDigestRegexp matches valid digests, anchored at the start and
	// end of the matched string.
	AnchoredDigestRegexp = re(anchored(digestPat))

	// TagRegexp matches valid tag names. From [docker/docker:graph/tags.go].
	//
	// [docker/docker:graph/tags.go]: https://github.com/moby/moby/blob/v1.6.0/graph/tags.go#L26-L28
	TagRegexp = re(tag)

	// AnchoredTagRegexp matches valid tags, anchored at the start and
	// end of the matched string.
	AnchoredTagRegexp = re(anchored(tag))

	// DomainRegexp matches hostname or IP-addresses, optionally including a port
	// number. It defines the structure of potential domain components that may be
	// part of image names. This is purposely a subset of what is allowed by DNS to
	// ensure backwards compatibility with Docker image names. It may be a subset of
	// DNS domain name, an IPv4 address in decimal format, or an IPv6 address between
	// square brackets (excluding zone identifiers as defined by [RFC 6874] or special
	// addresses such as IPv4-Mapped).
	//
	// [RFC 6874]: https://www.rfc-editor.org/rfc/rfc6874.
	DomainRegexp = re(domain)

	// AnchoredDomainRegexp matches valid domain, anchored at the start and
	// end of the matched string.
	AnchoredDomainRegexp = re(anchored(domain))

	// IdentifierRegexp is the format for string identifier used as a
	// content addressable identifier using sha256. These identifiers
	// are like digests without the algorithm, since sha256 is used.
	IdentifierRegexp = re(identifier)

	// AnchoredIdentifierRegexp is used to check or match an identifier value, anchored
	// at start and end of string.
	AnchoredIdentifierRegexp = re(anchored(identifier))

	// ShortIdentifierRegexp is the format used to represent a prefix
	// of an identifier. A prefix may be used to match a sha256 identifier
	// within a list of trusted identifiers.
	ShortIdentifierRegexp = re(shortIdentifier)

	// AnchoredShortIdentifierRegexp is used to check or match a prefix of an identifier,
	// anchored at start and end of string.
	AnchoredShortIdentifierRegexp = re(shortIdentifier)

	// RemoteNameRegexp is the format of the repository path without registry host prefix.
	RemoteNameRegexp = re(remoteName)

	// AnchoredRemoteNameRegexp is used to check or match a repository name without registry
	// host prefix, anchored at start and end of string.
	AnchoredRemoteNameRegexp = re(anchored(remoteName))

	// NameRegexp is the format for the name component of references, including
	// an optional domain and port, but without tag or digest suffix.
	NameRegexp = re(namePat)

	// AnchoredNameRegexp is used to parse a name value, capturing the
	// domain and trailing components.
	AnchoredNameRegexp = re(anchoredName)

	// ReferenceRegexp is the full supported format of a reference. The regexp
	// is anchored and has capturing groups for name, tag, and digest
	// components.
	ReferenceRegexp = re(referencePat)

	// AnchoredReferenceRegexp is used to check or match a reference value, anchored
	// at start and end of string.
	AnchoredReferenceRegexp = re(anchored(referencePat))

	// AnchoredSchemePrefixRegexp is used to check whether a domain contains http or https
	// prefix.
	AnchoredSchemePrefixRegexp = re(anchored(`(?P<prefix>.*://).*$`))
)

const (
	// alphaNumeric defines the alpha numeric atom, typically a
	// component of names. This only allows lower case characters and digits.
	alphaNumeric = `[a-z0-9]+`

	// separator defines the separators allowed to be embedded in name
	// components. This allow one period, one or two underscore and multiple
	// dashes. Repeated dashes and underscores are intentionally treated
	// differently. In order to support valid hostnames as name components,
	// supporting repeated dash was added. Additionally double underscore is
	// now allowed as a separator to loosen the restriction for previously
	// supported names.
	separator = `(?:[._]|__|[-]*)`

	// domainNameComponent restricts the registry domain component of a
	// repository name to start with a component as defined by DomainRegexp
	// and followed by an optional port.
	domainNameComponent = `(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])`

	// ipv6address are enclosed between square brackets and may be represented
	// in many ways, see rfc5952. Only IPv6 in compressed or uncompressed format
	// are allowed, IPv6 zone identifiers (rfc6874) or Special addresses such as
	// IPv4-Mapped are deliberately excluded.
	ipv6address = `\[(?:[a-fA-F0-9:]+)\]`

	// port defines the port number atom without port separator. (e.g. "80").
	port = `[0-9]+`

	// tag matches valid tag names. The string counterpart for TagRegexp.
	tag = `[\w][\w.-]{0,127}`

	// digestPat matches well-formed digests, including algorithm (e.g. "sha256:<encoded>").
	//
	// TODO(thaJeztah): this should follow the same rules as https://pkg.go.dev/github.com/opencontainers/go-digest@v1.0.0#DigestRegexp
	// so that go-digest defines the canonical format. Note that the go-digest is
	// more relaxed:
	//   - it allows multiple algorithms (e.g. "sha256+b64:<encoded>") to allow
	//     future expansion of supported algorithms.
	//   - it allows the "<encoded>" value to use urlsafe base64 encoding as defined
	//     in [rfc4648, section 5].
	//
	// [rfc4648, section 5]: https://www.rfc-editor.org/rfc/rfc4648#section-5.
	digestPat = `[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][[:xdigit:]]{32,}`

	// identifier is the format for a content addressable identifier using sha256.
	// These identifiers are like digests without the algorithm, since sha256 is used.
	identifier = `([a-f0-9]{64})`

	// shortIdentifier is the string counterpart for ShortIdentifierRegexp.
	shortIdentifier = `([a-f0-9]{6,64})`
)

var (
	// domainName defines the structure of potential domain components
	// that may be part of image names. This is purposely a subset of what is
	// allowed by DNS to ensure backwards compatibility with Docker image
	// names. This includes IPv4 addresses on decimal format.
	domainName = expression(
		domainNameComponent,
		optional(repeated(literal(`.`), domainNameComponent)),
	)

	// host defines the structure of potential domains based on the URI
	// Host subcomponent on rfc3986. It may be a subset of DNS domain name,
	// or an IPv4 address in decimal format, or an IPv6 address between square
	// brackets (excluding zone identifiers as defined by rfc6874 or special
	// addresses such as IPv4-Mapped).
	host = expression(domainName, `|`, ipv6address)

	// domain allowed by the URI Host subcomponent on rfc3986 to ensure backwards
	// compatibility with Docker image names.
	domain = expression(group(host), optional(literal(`:`), port))

	// pathComponent restricts path-components to start with an alphanumeric
	// character, with following parts able to be separated by a separator
	// (one period, one or two underscore and multiple dashes).
	//
	// Format: alphanumeric [separator alphanumeric]*
	pathComponent = expression(
		alphaNumeric,
		optional(repeated(separator, alphaNumeric)),
	)

	// remoteName matches the remote-name of a repository without registry host.
	// It consists of one or more forward slash (/) delimited path-components:
	//
	// Format: path-component ['/' path-component]*
	//
	// Example: library/ubuntu
	remoteName = expression(
		pathComponent,
		optional(repeated(literal(`/`), pathComponent)),
	)

	// namePat matches the repository with registry host.
	//
	// Format: [domain '/'] path-component ['/' path-component]*
	namePat = expression(
		optional(domain, literal(`/`)),
		remoteName,
	)

	anchoredName = anchored(
		optional(capture(domain), literal(`/`)),
		capture(remoteName),
	)

	// referencePat matches the reference string.
	//
	// Format: name [ ":" tag ] [ "@" digest ]
	referencePat = expression(capture(namePat),
		optional(literal(":"), capture(tag)),
		optional(literal("@"), capture(digestPat)),
	)
)
