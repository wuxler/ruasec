// Package main is the entry of the application.
package main

import (
	"context"
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/wuxler/ruasec/pkg/cmd"
)

const (
	appName = "rua"
)

func main() {
	app := cli.Command{
		Name:                  appName,
		Usage:                 "Rua is a tool to do security checks",
		Suggest:               true,
		EnableShellCompletion: true,
		HideVersion:           true,
		Commands: []*cli.Command{
			cmd.NewVersionCommand().ToCLI(),
		},
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
