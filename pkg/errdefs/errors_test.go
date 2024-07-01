package errdefs_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/wuxler/ruasec/pkg/errdefs"
)

var errTest = errors.New("this is a test")

func TestErrors(t *testing.T) {
	testcases := []struct {
		name string
		err  error
	}{
		{"NotFound", errdefs.ErrNotFound},
		{"InvalidParameter", errdefs.ErrInvalidParameter},
		{"Conflict", errdefs.ErrConflict},
		{"Unauthorized", errdefs.ErrUnauthorized},
		{"Unavailable", errdefs.ErrUnavailable},
		{"Forbidden", errdefs.ErrForbidden},
		{"System", errdefs.ErrSystem},
		{"NotImplemented", errdefs.ErrNotImplemented},
		{"Unknown", errdefs.ErrUnknown},
		{"Canceled", errdefs.ErrCanceled},
		{"DeadlineExceeded", errdefs.ErrDeadlineExceeded},
		{"DataLoss", errdefs.ErrDataLoss},
		{"AlreadyExists", errdefs.ErrAlreadyExists},
		{"Unsupported", errdefs.ErrUnsupported},
		{"UnsupportedVersion", errdefs.ErrUnsupportedVersion},
	}

	for _, tc := range testcases {
		t.Run("NewE_"+tc.name, func(t *testing.T) {
			assert.NotErrorIs(t, errTest, tc.err)
			e := errdefs.NewE(tc.err, errTest)
			assert.ErrorIs(t, e, tc.err)
		})
	}

	for _, tc := range testcases {
		t.Run("Newf_"+tc.name, func(t *testing.T) {
			e := errdefs.Newf(tc.err, "this is a test")
			assert.ErrorIs(t, e, tc.err)
		})
	}
}
