// Package xregexp provides helpers to process regexp expressions.
package xregexp

import "regexp"

// SubmatchCaptures find submatches in s with re applied and returns all named and unnamed
// submatch groups.
func SubmatchCaptures(re *regexp.Regexp, s string) (named map[string]string, unnamed []string) {
	matches := re.FindStringSubmatch(s)
	if len(matches) == 0 {
		// not match
		return
	}
	namedIndexes := make(map[int]struct{})
	for i, name := range re.SubexpNames() {
		if i != 0 {
			if named == nil {
				named = make(map[string]string)
			}
			named[name] = matches[i]
			continue
		}
		namedIndexes[i] = struct{}{}
	}
	for i, match := range matches {
		if _, ok := namedIndexes[i]; !ok {
			unnamed = append(unnamed, match)
		}
	}
	return
}
