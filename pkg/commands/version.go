package commands

import (
	"context"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/appinfo"
	"github.com/wuxler/ruasec/pkg/cmdhelper"
)

// NewVersionCommand returns a version command.
func NewVersionCommand() *VersionCommand {
	return &VersionCommand{
		Format: "text",
	}
}

// VersionCommand is a generic version command for applications.
type VersionCommand struct {
	Short  bool
	Format string
}

// ToCLI returns a *cli.Command.
func (c *VersionCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:   "version",
		Usage:  "Show version",
		Flags:  c.Flags(),
		Before: cli.BeforeFunc(cmdhelper.NoArgs()),
		Action: c.Run,
	}
}

// Run implements *cli.Command Action function.
func (c *VersionCommand) Run(_ context.Context, cmd *cli.Command) error {
	return appinfo.NewVersionWriter(appinfo.GetVersion()).
		SetShort(c.Short).
		SetFormat(c.Format).
		SetAppName(cmd.Root().Name).
		Write(cmd.Writer)
}

// Flags returns a list of cli flags of the commands.
func (c *VersionCommand) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "short",
			Aliases:     []string{"s"},
			Usage:       "short output",
			Value:       c.Short,
			Destination: &c.Short,
		},
		&cli.StringFlag{
			Name:        "format",
			Aliases:     []string{"f"},
			Usage:       `output format, oneof ["text", "json", "yaml"]`,
			Value:       c.Format,
			Destination: &c.Format,
		},
	}
}
