package registry

import "github.com/urfave/cli/v3"

func New() *RegistryCommand {
	return &RegistryCommand{}
}

type RegistryCommand struct {
	Insecure bool
	CAFiles  []string
}

func (c *RegistryCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "registry",
		Aliases: []string{"reg"},
		Flags:   c.Flags(),
		Commands: []*cli.Command{
			NewLoginCommand(c).ToCLI(),
			NewLogoutCommand(c).ToCLI(),
		},
	}
}

func (c *RegistryCommand) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "insecure",
			Usage:       "enable to skip verify registry SSL certificate",
			Sources:     cli.EnvVars("RUA_REGISTRY_INSECURE"),
			Destination: &c.Insecure,
			Value:       c.Insecure,
			Persistent:  true,
		},
		&cli.StringSliceFlag{
			Name:        "ca-files",
			Usage:       "specify CA files to verify registry SSL certificate",
			Destination: &c.CAFiles,
			Value:       c.CAFiles,
			Persistent:  true,
		},
	}
}
