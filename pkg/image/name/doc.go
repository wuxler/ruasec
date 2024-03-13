// Package name provides a general type to represent any way of referencing images within the registry.
// Its main purpose is to abstract tags and digests (content-addressable hash).
//
// # Grammar
//
//	reference                       := name [ ":" tag ] [ "@" digest ]
//	name                            := [domain '/'] remote-name
//	domain                          := host [':' port-number]
//	host                            := domain-name | IPv4address | \[ IPv6address \]	; rfc3986 appendix-A
//	domain-name                     := domain-component ['.' domain-component]*
//	domain-component                := /([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])/
//	port-number                     := /[0-9]+/
//	path-component                  := alpha-numeric [separator alpha-numeric]*
//	path (or "remote-name")         := path-component ['/' path-component]*
//	alpha-numeric                   := /[a-z0-9]+/
//	separator                       := /[_.]|__|[-]*/
//
//	tag                             := /[\w][\w.-]{0,127}/
//
//	digest                          := digest-algorithm ":" digest-hex
//	digest-algorithm                := digest-algorithm-component [ digest-algorithm-separator digest-algorithm-component ]*
//	digest-algorithm-separator      := /[+.-_]/
//	digest-algorithm-component      := /[A-Za-z][A-Za-z0-9]*/
//	digest-hex                      := /[0-9a-fA-F]{32,}/ ; At least 128 bit digest value
//
//	identifier                      := /[a-f0-9]{64}/
//
// # NOTE
//
// This package is draw inspiration deeply from the follow repositories:
//   - github.com/docker/distribution/reference
//   - oras.land/oras-go/v2/registry/reference.go
//   - github.com/google/go-containerregistry/pkg/name
package name
