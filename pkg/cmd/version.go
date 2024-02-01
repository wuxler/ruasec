package cmd

import (
	"context"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/appinfo"
)

func NewVersionCommand() *VersionCommand {
	return &VersionCommand{
		Format: "text",
	}
}

type VersionCommand struct {
	Short  bool
	Format string
}

func (c *VersionCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:   "version",
		Usage:  "Show version",
		Flags:  c.Flags(),
		Before: cli.BeforeFunc(NoArgs()),
		Action: c.Run,
	}
}

func (c *VersionCommand) Run(_ context.Context, cmd *cli.Command) error {
	return appinfo.NewVersionWriter(appinfo.GetVersion()).
		SetShort(c.Short).
		SetFormat(c.Format).
		SetAppName(cmd.Root().Name).
		Write(cmd.Writer)
}

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
