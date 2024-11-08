// Package main is the entry of the application.
package main

import (
	"context"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/commands"
	"github.com/wuxler/ruasec/pkg/commands/image"
	"github.com/wuxler/ruasec/pkg/commands/registry"
)

func main() {
	app := cli.Command{
		Name:                  "ruasec",
		Usage:                 "ruasec is a helpful tool to do security checks",
		Suggest:               true,
		EnableShellCompletion: true,
		HideVersion:           true,
		HideHelpCommand:       true,
		Commands: []*cli.Command{
			commands.NewVersionCommand().ToCLI(),
			registry.New().ToCLI(),
			image.New().ToCLI(),
		},
		ExitErrHandler: func(ctx context.Context, c *cli.Command, err error) {
			cli.HandleExitCoder(err)
			cmdhelper.Fprintf(c.ErrWriter, "Error: %+v\n", err)
			os.Exit(1)
		},
	}
	//nolint:errcheck // already checked in root command ExitErrHandler
	_ = app.Run(context.Background(), os.Args)
}
