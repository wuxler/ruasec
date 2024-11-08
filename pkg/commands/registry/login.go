package registry

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/commands/internal/options"
	"github.com/wuxler/ruasec/pkg/ocispec/authn"
	"github.com/wuxler/ruasec/pkg/ocispec/authn/authfile"
	"github.com/wuxler/ruasec/pkg/ocispec/authn/credentials"
	ocispecname "github.com/wuxler/ruasec/pkg/ocispec/name"
)

// NewLoginCommand returns a LoginCommand with default values.
func NewLoginCommand() *LoginCommand {
	return &LoginCommand{
		Common: options.NewCommon(),
		Remote: options.NewContainerRegistry(),
	}
}

// LoginCommand used to login remote registry.
type LoginCommand struct {
	Common *options.Common
	Remote *options.ContainerRegistry

	Username      string `json:"username,omitempty" yaml:"username,omitempty"`
	Password      string `json:"password,omitempty" yaml:"password,omitempty"`
	PasswordStdin bool   `json:"password_stdin,omitempty" yaml:"password_stdin,omitempty"`
}

// ToCLI tranforms to a *cli.Command.
func (c *LoginCommand) ToCLI() *cli.Command {
	return &cli.Command{
		Name:  "login",
		Usage: "Log in to a remote registry",
		UsageText: `ruasec registry login [OPTIONS] REGISTRY

# Log in with an interactive terminal:
$ ruasec registry login registry.example.com

# Log in with username and password from command line flags:
$ ruasec registry login -u username -p password registry.example.com

# Log in with username and password from stdin:
$ cat password.txt | ruasec registry login -u username --password-stdin registry.example.com

# Log in the private registry deployed with self-signed ssl certificate:
$ ruasec registry login --insecure registry.example.com
`,
		ArgsUsage: "REGISTRY",
		Flags:     c.Flags(),
		Before:    cli.BeforeFunc(c.Validate),
		Action:    c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *LoginCommand) Flags() []cli.Flag {
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:        "username",
			Aliases:     []string{"u"},
			Usage:       "registry username",
			Sources:     cli.EnvVars("RUASEC_REGISTRY_USERNAME", "DOCKER_USERNAME"),
			Destination: &c.Username,
			Value:       c.Username,
		},
		&cli.StringFlag{
			Name:        "password",
			Aliases:     []string{"p"},
			Usage:       "registry password",
			Sources:     cli.EnvVars("RUASEC_REGISTRY_PASSWORD", "DOCKER_PASSWORD"),
			Destination: &c.Password,
			Value:       c.Password,
		},
		&cli.BoolFlag{
			Name:        "password-stdin",
			Usage:       "take password from stdin input",
			Sources:     cli.EnvVars("RUASEC_REGISTRY_PASSWORD_STDIN"),
			Destination: &c.PasswordStdin,
			Value:       c.PasswordStdin,
		},
	}
	flags = append(flags, c.Remote.Flags()...)
	flags = append(flags, c.Common.Flags()...)
	return flags
}

// Validate validates commands flags.
func (c *LoginCommand) Validate(ctx context.Context, cmd *cli.Command) error {
	if c.Password != "" {
		cmdhelper.Fprintf(cmd.Writer, "Warning: Using --password via the CLI is insecure. Use --password-stdin instead")
		if c.PasswordStdin {
			return errors.New("--password and --password-stdin are mutually exclusive")
		}
	}
	if c.PasswordStdin {
		if c.Username == "" {
			return errors.New("must provide --username with --password-stdin")
		}
		password, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		c.Password = strings.TrimRight(string(password), "\n\r")
	}
	return nil
}

// Run is the main function for the current command
func (c *LoginCommand) Run(ctx context.Context, cmd *cli.Command) error {
	if err := c.run(ctx, cmd); err != nil {
		return err
	}
	cmdhelper.Fprintf(cmd.Writer, "Login succeeded")
	return nil
}

func (c *LoginCommand) run(ctx context.Context, cmd *cli.Command) error {
	serverAddress, _ := cmdhelper.ElectDockerServerAddress(ctx, cmd, cmd.Args().First())
	serverAddressName, err := ocispecname.NewRegistry(serverAddress)
	if err != nil {
		return err
	}

	authFile := authfile.NewAuthFile(c.Remote.AuthFile)
	if err := authFile.Load(); err != nil {
		cmdhelper.Fprintf(cmd.Writer, "Warning: Failed to load auth file: %s", err)
	}
	client, err := c.Remote.NewClient(cmd.Writer)
	if err != nil {
		return err
	}

	if c.Password == "" && c.Username == "" {
		// try to login with the crendetial found in default auth files
		client.AuthProvider = func(ctx context.Context, host string) authn.AuthConfig {
			authConfig, err := authFile.Get(ctx, host)
			if err == nil && authConfig != authn.EmptyAuthConfig {
				cmdhelper.Fprintf(cmd.Writer, "Authenticating with existing credentials ...")
			}
			return authConfig
		}
		registry, err := client.NewRegistry(ctx, serverAddressName)
		if err != nil {
			return err
		}
		if err := registry.Ping(ctx); err != nil {
			return err
		}
	}

	if c.Password == "" || c.Username == "" {
		// prompt for credential
		if err := c.promptUserInput(); err != nil {
			return err
		}
	}
	authConfig := authn.AuthConfig{
		Username: c.Username,
		Password: c.Password,
	}
	client.AuthProvider = func(_ context.Context, _ string) authn.AuthConfig {
		return authConfig
	}

	registry, err := client.NewRegistry(ctx, serverAddressName)
	if err != nil {
		return err
	}
	if err := registry.Ping(ctx); err != nil {
		return err
	}
	// store the validate credential
	cmdhelper.Fprintf(cmd.Writer, "Warning: Your password will be stored unencryped in %s", c.Remote.AuthFile)
	store := credentials.NewFileStore(authFile)
	if err := store.Store(ctx, serverAddress, authConfig); err != nil {
		return err
	}
	return nil
}

func (c *LoginCommand) promptUserInput() error {
	if c.Username == "" {
		prompt := promptui.Prompt{
			Label: "Username",
		}
		username, err := prompt.Run()
		if err != nil {
			return err
		}
		c.Username = username
	}
	if c.Username == "" {
		return errors.New("non-empty username is required")
	}

	if c.Password == "" {
		prompt := promptui.Prompt{
			Label: "Password",
			Mask:  '*',
		}
		password, err := prompt.Run()
		if err != nil {
			return err
		}
		c.Password = password
	}
	if c.Password == "" {
		return errors.New("non-empty username is required")
	}
	return nil
}
