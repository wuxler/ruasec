package xcontext

import (
	"context"
	"fmt"
	"strings"
)

// NonBlockingCheck checks context as non-blocking select and returns error if context is done.
func NonBlockingCheck(ctx context.Context, msgs ...string) error {
	select {
	case <-ctx.Done():
		if len(msgs) == 0 {
			return ctx.Err()
		}
		return fmt.Errorf("%s: %w", strings.Join(msgs, ":"), ctx.Err())
	default:
	}
	return nil
}
