package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/samber/lo"
	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/commands"
	"github.com/wuxler/ruasec/pkg/image/name"
	"github.com/wuxler/ruasec/pkg/ocispec/authn/authfile"
	"github.com/wuxler/ruasec/pkg/ocispec/authn/credentials"
)

// NewLogoutCommand returns a LogoutCommand with default values.
func NewLogoutCommand(registryCmd *RegistryCommand) *LogoutCommand {
	return &LogoutCommand{
		RegistryCommand: registryCmd,
		AuthFile:        commands.DefaultAuthFile(),
	}
}

// LogoutCommand used to remove the credentials from the local auth file.
type LogoutCommand struct {
	*RegistryCommand
	AuthFile string `json:"auth_file,omitempty" yaml:"auth_file,omitempty"`
}

// ToCLI transforms to a *cli.Command.
func (c *LogoutCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:  "logout",
		Usage: "Log out and remove credentials for a remote registry",
		UsageText: `rua registry logout [OPTIONS] REGISTRY

# Log out from a remote registry
$ rua registry logout registry.example.com
`,
		ArgsUsage: "REGISTRY",
		Flags:     c.Flags(),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *LogoutCommand) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "auth-file",
			Usage:       "registry auth file path",
			Sources:     cli.EnvVars("RUA_REGISTRY_AUTH_FILE"),
			Destination: &c.AuthFile,
			Value:       c.AuthFile,
		},
	}
}

// Run is the main function for the current command
func (c *LogoutCommand) Run(ctx context.Context, cmd *cli.Command) error {
	authFile := authfile.NewAuthFile(c.AuthFile)
	if err := authFile.Load(); err != nil {
		commands.Fprintf(cmd.Writer, "Warning: Failed to load auth file: %s", err)
	}
	store := credentials.NewFileStore(authFile)

	serverAddress, isDefaultServer := commands.ElectServerAddress(ctx, cmd, cmd.Args().First())
	serversToLogout := []string{serverAddress}
	serverHostname := serverAddress
	if !isDefaultServer {
		serverHostname = name.Hostname(serverAddress)
		// the tries below are kept for backward compatibility where a user could have
		// saved the registry in one of the following format.
		serversToLogout = append(serversToLogout,
			serverHostname,
			"http://"+serverHostname,
			"https://"+serverHostname,
		)
		serversToLogout = lo.Uniq(serversToLogout)
	}

	commands.Fprintf(cmd.Writer, "Removing login credentials for %s", serverHostname)
	var errs []error
	for _, server := range serversToLogout {
		if err := store.Erase(ctx, server); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", server, err))
		}
	}
	if len(errs) == len(serversToLogout) {
		commands.Fprintf(cmd.Writer, "Warning: could not erase credentials: %s", errors.Join(errs...))
	}

	return nil
}
