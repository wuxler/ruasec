package xregexp

import (
	"regexp"
	"strings"
)

// Literal compiles s into a Literal regular expression, escaping any regexp
// reserved characters.
func Literal(s string) string {
	return regexp.QuoteMeta(s)
}

// Expression defines a full Expression, where each regular Expression must
// follow the previous.
func Expression(res ...string) string {
	return strings.Join(res, "")
}

// Optional wraps the expression in a non-capturing group and makes the
// production Optional.
func Optional(res ...string) string {
	return Group(Expression(res...)) + `?`
}

// Repeated wraps the regexp in a non-capturing group to get one or more
// matches.
func Repeated(res ...string) string {
	return Group(Expression(res...)) + `+`
}

// Any wraps the regexp in a non-capturing group and make zero or more
// matches.
//
// NOTE: "Any(res...)" equal to "optional(repeated(res...))"
func Any(res ...string) string {
	return Group(Expression(res...)) + "*"
}

// Group wraps the regexp in a non-capturing Group.
func Group(res ...string) string {
	return `(?:` + Expression(res...) + `)`
}

// Capture wraps the expression in a capturing group.
func Capture(res ...string) string {
	return `(` + Expression(res...) + `)`
}

// Anchored anchors the regular expression by adding start and end delimiters.
func Anchored(res ...string) string {
	return `^` + Expression(res...) + `$`
}
