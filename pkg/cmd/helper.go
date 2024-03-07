// Package cmd provides common methods or types to help to build cli commands.
package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
)

// ActionFunc is a function type to set *cli.Command Action
type ActionFunc func(ctx context.Context, cmd *cli.Command) error

// ActionFuncChain wraps multiple ActionFunc into one process.
func ActionFuncChain(handlers ...ActionFunc) ActionFunc {
	return func(ctx context.Context, cmd *cli.Command) error {
		for _, h := range handlers {
			if err := h(ctx, cmd); err != nil {
				return err
			}
		}
		return nil
	}
}

// ExactArgs returns an error if there are not exactly n args.
func ExactArgs(n int) ActionFunc {
	return func(_ context.Context, cmd *cli.Command) error {
		args := cmd.Args()
		if args.Len() != n {
			return fmt.Errorf("accepts %d arg(s), received %d", n, args.Len())
		}
		return nil
	}
}

// MinimumNArgs returns an error if there is not at least N args.
func MinimumNArgs(n int) ActionFunc {
	return func(_ context.Context, cmd *cli.Command) error {
		args := cmd.Args()
		if args.Len() < n {
			return fmt.Errorf("accepts at least %d arg(s), received %d", n, args.Len())
		}
		return nil
	}
}

// MaximumNArgs returns an error if there are more than N args.
func MaximumNArgs(n int) ActionFunc {
	return func(_ context.Context, cmd *cli.Command) error {
		args := cmd.Args()
		if args.Len() > n {
			return fmt.Errorf("accepts at most %d arg(s), received %d", n, args.Len())
		}
		return nil
	}
}

// NoArgs returns an error if any args are included.
func NoArgs() ActionFunc {
	return func(_ context.Context, cmd *cli.Command) error {
		args := cmd.Args()
		if args.Len() > 0 {
			return fmt.Errorf("no args required for %q, received %q", cmd.FullName(), args.First())
		}
		return nil
	}
}
