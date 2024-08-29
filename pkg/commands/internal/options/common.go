package options

import (
	"github.com/urfave/cli/v3"

	ocispecremote "github.com/wuxler/ruasec/pkg/ocispec/remote"
	"github.com/wuxler/ruasec/pkg/util/xhttp"
)

// NewCommonOptions returns a *CommonOptions with default values.
func NewCommonOptions() *CommonOptions {
	return &CommonOptions{}
}

// CommonOptions are options that are common to all commands.
type CommonOptions struct {
	Debug bool `json:"debug,omitempty" yaml:"debug,omitempty"`
}

// Flags returns the []cli.Flag related to current options.
func (o *CommonOptions) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "debug",
			Aliases:     []string{"d"},
			Sources:     cli.EnvVars("RUA_DEBUG"),
			Usage:       "enable debug mode",
			Destination: &o.Debug,
		},
	}
}

// ApplyDistributionClient applies common options to the distribution client.
func (o *CommonOptions) ApplyDistributionClient(c *ocispecremote.Client) {
	if o.Debug && c.Client.Transport != nil {
		c.Client.Transport = xhttp.NewDumpTransport(c.Client.Transport)
	}
}
