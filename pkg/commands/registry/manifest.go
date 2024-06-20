package registry

import (
	"context"
	"fmt"
	"io"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/commands/internal/options"
	"github.com/wuxler/ruasec/pkg/image/name"
	"github.com/wuxler/ruasec/pkg/util/xio"
)

// NewManifestCommand returns a ManifestCommand with default values.
func NewManifestCommand() *ManifestCommand {
	return &ManifestCommand{
		Fetch: NewManifestFetchCommand(),
	}
}

// ManifestCommand defines manifest operations.
type ManifestCommand struct {
	Fetch *ManifestFetchCommand
	// TODO: implement push command
	// TODO: implement delete command
}

// ToCLI transforms to a *cli.Command.
func (c *ManifestCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:  "manifest",
		Usage: "Manifest operations",
		Commands: []*cli.Command{
			c.Fetch.ToCLI(),
		},
		CommandNotFound: func(ctx context.Context, c *cli.Command, s string) {
			cli.ShowSubcommandHelpAndExit(c, 1)
		},
	}
}

// NewManifestFetchCommand returns a manifest fetch command with default values.
func NewManifestFetchCommand() *ManifestFetchCommand {
	return &ManifestFetchCommand{
		RemoteRegistryOptions: options.NewRemoteRegistryOptions(),
	}
}

// ManifestFetchCommand used to fetch the image manifest from the remote registry.
type ManifestFetchCommand struct {
	*options.RemoteRegistryOptions
	Pretty     bool `json:"pretty,omitempty" yaml:"pretty,omitempty"`
	Descriptor bool `json:"descriptor,omitempty" yaml:"descriptor,omitempty"`
}

// ToCLI transforms to a *cli.Command.
func (c *ManifestFetchCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "fetch",
		Aliases: []string{"get"},
		Usage:   "Get the manifest of an image",
		UsageText: `rua registry manifest fetch [OPTIONS] IMAGE

# Log out from a remote registry
$ rua registry manifest fetch hello-world:latest
`,
		ArgsUsage: "IMAGE",
		Flags:     c.Flags(),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *ManifestFetchCommand) Flags() []cli.Flag {
	local := []cli.Flag{
		&cli.BoolFlag{
			Name:        "pretty",
			Usage:       "prettify to output",
			Destination: &c.Pretty,
			Value:       c.Pretty,
		},
		&cli.BoolFlag{
			Name:        "descriptor",
			Aliases:     []string{"desc"},
			Usage:       "only output descriptor of the manifest",
			Destination: &c.Descriptor,
			Value:       c.Descriptor,
		},
	}
	return append(c.RemoteRegistryOptions.Flags(), local...)
}

// Run is the main function for the current command
func (c *ManifestFetchCommand) Run(ctx context.Context, cmd *cli.Command) error {
	target, err := name.NewReference(cmd.Args().First())
	if err != nil {
		return err
	}
	tagOrDigest, err := name.Identify(target)
	if err != nil {
		return err
	}

	client, err := c.NewDistributionClient()
	if err != nil {
		return err
	}
	registryClient, err := client.NewRegistryWithContext(ctx, target.Repository().Domain().String())
	if err != nil {
		return err
	}
	rc, err := registryClient.GetManifest(ctx, target.Repository().Path(), tagOrDigest)
	if err != nil {
		return err
	}
	defer xio.CloseAndSkipError(rc)

	if c.Descriptor {
		desc := rc.Descriptor()
		content, err := cmdhelper.PrettifyJSON(desc)
		if err != nil {
			return err
		}
		cmdhelper.Fprintf(cmd.Writer, "%s\n", string(content))
		return nil
	}

	content, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	if c.Pretty {
		if content, err = cmdhelper.PrettifyJSON(content); err != nil {
			return err
		}
		cmdhelper.Fprintf(cmd.Writer, "%s\n", string(content))
		return nil
	}

	_, err = fmt.Fprint(cmd.Writer, string(content))
	return err
}
