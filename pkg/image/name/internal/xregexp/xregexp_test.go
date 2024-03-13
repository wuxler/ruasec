package xregexp_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/wuxler/ruasec/pkg/image/name/internal/xregexp"
)

func TestSubmatchCaptures(t *testing.T) {
	testcases := map[string]struct {
		re     *regexp.Regexp
		target string
		expect map[string]string
	}{
		"happy test license filter": {
			re:     regexp.MustCompile(`(?i)(?P<License>\w+) - see license.*`),
			target: "PSF - see LICENSE",
			expect: map[string]string{
				"License": "PSF",
			},
		},
		"happy test date format": {
			re:     regexp.MustCompile(`(?P<Year>\d{4})-(?P<Month>\d{2})-(?P<Day>\d{2})`),
			target: "2021-08-02",
			expect: map[string]string{
				"Year":  "2021",
				"Month": "08",
				"Day":   "02",
			},
		},
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			params, _ := xregexp.SubmatchCaptures(tc.re, tc.target)
			assert.Equal(t, tc.expect, params)
		})
	}
}
