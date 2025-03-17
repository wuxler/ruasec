package options

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/appinfo"
	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/util/xhttp"
	"github.com/wuxler/ruasec/pkg/xlog"
)

// NewCommon returns a *CommonOptions with default values.
func NewCommon() *Common {
	return &Common{
		Workspace: string(appinfo.GetWorkspace()),
	}
}

// Common are options that are common to all commands.
type Common struct {
	Debug     bool   `json:"debug,omitempty" yaml:"debug,omitempty"`
	Workspace string `json:"workspace,omitempty" yaml:"workspace,omitempty"`
}

// Flags returns the []cli.Flag related to current options.
func (o *Common) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "debug",
			Aliases:     []string{"d"},
			Sources:     cli.EnvVars("RUA_DEBUG"),
			Usage:       "enable debug mode",
			Destination: &o.Debug,
		},
		&cli.StringFlag{
			Name:        "workspace",
			Aliases:     []string{"w"},
			Sources:     cli.EnvVars("RUA_WORKSPACE"),
			Usage:       "workspace directory",
			Destination: &o.Workspace,
		},
	}
}

// Init implements [cmdhelper.ActionFunc] and setups global configurations.
func (o *Common) Init(_ context.Context, _ *cli.Command) error {
	if o.Debug {
		xlog.SetLevel(xlog.LevelDebug)
	}
	appinfo.SetWorkspace(o.Workspace)
	return nil
}

// NewRemote returns the options with default values.
func NewRemote() *Remote {
	return &Remote{}
}

// Remote defines the options for remote access.
type Remote struct {
	Insecure   bool     `json:"insecure,omitempty" yaml:"insecure,omitempty"`
	TLSCAFiles []string `json:"tls_ca_files,omitempty" yaml:"tls_ca_files,omitempty"`
	DumpEnable bool     `json:"dump_enable,omitempty" yaml:"dump_enable,omitempty"`
}

// Flags returns the cli flags related to current options.
func (o *Remote) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "insecure",
			Usage:       "enable to skip verify server SSL certificate",
			Sources:     cli.EnvVars("RUASEC_REMOTE_INSECURE"),
			Destination: &o.Insecure,
			Value:       o.Insecure,
		},
		&cli.StringSliceFlag{
			Name:        "tls-ca-files",
			Usage:       "specify CA files to verify server SSL certificate",
			Destination: &o.TLSCAFiles,
			Value:       o.TLSCAFiles,
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
		&cli.BoolFlag{
			Name:        "dump-enable",
			Usage:       "enable to dump http request and response",
			Sources:     cli.EnvVars("RUASEC_REMOTE_DUMP_ENABLE"),
			Destination: &o.DumpEnable,
			Value:       o.DumpEnable,
		},
	}
}

// NewHTTPTransport returns a new http transport with options.
func (o *Remote) NewHTTPTransport(w io.Writer) (http.RoundTripper, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone() //nolint:errcheck // explicitly type assertion
	// load tls config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: o.Insecure, //nolint:gosec // explicit skip verify
	}
	if len(o.TLSCAFiles) > 0 {
		if len(o.TLSCAFiles) > 0 {
			pool, err := cmdhelper.LoadTLSCertFiles(o.TLSCAFiles...)
			if err != nil {
				return nil, err
			}
			tlsConfig.RootCAs = pool
		}
	}
	tr.TLSClientConfig = tlsConfig
	if o.DumpEnable {
		dump := xhttp.NewDumpTransport(tr)
		if w != nil {
			dump.Out = w
		}
		return dump, nil
	}
	return tr, nil
}
