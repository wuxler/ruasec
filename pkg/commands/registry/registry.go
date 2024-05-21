package registry

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/ocispec/distribution"
)

// New creates a new RegistryCommand
func New() *RegistryCommand {
	return &RegistryCommand{}
}

// RegistryCommand is a command for registry and retains the common flags for subcommands.
type RegistryCommand struct {
	Insecure bool
	CAFiles  []string
}

// ToCLI tranforms to a *cli.Command.
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

// Flags defines the flags related to the current command.
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
			Validator: func(paths []string) error {
				var errs []error
				for _, path := range paths {
					if _, err := os.ReadFile(path); err != nil {
						errs = append(errs, err)
					}
				}
				return errors.Join(errs...)
			},
		},
	}
}

// NewClient returns a new *distribution.Client with flags configured.
func (c *RegistryCommand) NewClient() (*distribution.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// load tls config
	var tlsConfig *tls.Config
	if c.Insecure || len(c.CAFiles) > 0 {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: c.Insecure, //nolint:gosec // explicit skip verify
		}
		if len(c.CAFiles) > 0 {
			pool, err := loadCertFiles(c.CAFiles...)
			if err != nil {
				return nil, err
			}
			tlsConfig.RootCAs = pool
		}
	}
	tr.TLSClientConfig = tlsConfig

	client := &distribution.Client{
		Client: &http.Client{
			Transport: tr,
		},
	}
	return client, nil
}

func loadCertFiles(paths ...string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, path := range paths {
		pemCerts, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if ok := pool.AppendCertsFromPEM(pemCerts); !ok {
			return nil, fmt.Errorf("unable to append certs from pem file %s: %w", path, err)
		}
	}
	return pool, nil
}
