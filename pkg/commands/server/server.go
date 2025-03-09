package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/cmdhelper"
	"github.com/wuxler/ruasec/pkg/commands/internal/options"
	"github.com/wuxler/ruasec/pkg/xlog"
)

// New creates a new ServerCommand.
func New() *Command {
	return NewCommand()
}

// NewCommand returns a command with default values.
func NewCommand() *Command {
	return &Command{
		ServerOptions: options.NewServerOptions(),
	}
}

// Command is a command to start the server.
type Command struct {
	ServerOptions *options.ServerOptions
}

// ToCLI transforms to a *cli.Command.
func (c *Command) ToCLI() *cli.Command {
	return &cli.Command{
		Name:    "server",
		Aliases: []string{"srv"},
		Usage:   "Start the server in service mode",
		UsageText: `ruasec server [OPTIONS]

# Start the server with default port 8080
$ ruasec server

# Start the server with custom port
$ ruasec server --port 9000
`,
		Flags:  c.Flags(),
		Action: c.Run,
	}
}

// Flags defines the flags related to the current command.
func (c *Command) Flags() []cli.Flag {
	flags := []cli.Flag{}
	flags = append(flags, c.ServerOptions.Flags()...)
	return flags
}

// Run is the main function for the current command
func (c *Command) Run(ctx context.Context, cmd *cli.Command) error {
	address := c.ServerOptions.Address()
	xlog.C(ctx).Infof("Starting server %s", address)

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Define routes
	router.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Start the HTTP server
	srv := &http.Server{
		Addr:              address,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			xlog.C(ctx).Error("Server error", "error", err)
		}
	}()

	cmdhelper.Fprintf(cmd.Writer, "Server started at http://%s\n", address)
	cmdhelper.Fprintf(cmd.Writer, "Press Ctrl+C to stop the server\n")

	// Wait for interrupt signal
	<-ctx.Done()

	// Create a timeout context for shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second) //nolint:gomnd // disable magic number lint error
	defer cancel()

	// Shutdown the server
	if err := srv.Shutdown(shutdownCtx); err != nil {
		xlog.C(ctx).Error("Server shutdown failed", "error", err)
		return err
	}

	xlog.C(ctx).Info("Server stopped")
	return nil
}
