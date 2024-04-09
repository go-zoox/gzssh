package commands

import (
	"fmt"
	"os"

	"github.com/go-zoox/cli"
	"github.com/go-zoox/fs"
	"github.com/go-zoox/gzssh/client"
)

func RegistryClient(app *cli.MultipleProgram) {
	homeDir, _ := os.UserHomeDir()
	app.Register("client", &cli.Command{
		Name:  "client",
		Usage: "start a ssh client",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "host",
				Usage:    "server host",
				EnvVars:  []string{"SSH_HOST"},
				Required: true,
			},
			&cli.IntFlag{
				Name:    "port",
				Usage:   "server port",
				Aliases: []string{"p"},
				EnvVars: []string{"SSH_PORT"},
				Value:   22,
			},
			&cli.StringFlag{
				Name:     "user",
				Usage:    "server user",
				Aliases:  []string{"u"},
				EnvVars:  []string{"SSH_USER"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "pass",
				Usage:   "server pass",
				Aliases: []string{},
				EnvVars: []string{"SSH_PASS"},
			},
			&cli.StringFlag{
				Name:    "private-key",
				Aliases: []string{"i"},
				Usage:   "server private key file path",
				EnvVars: []string{"SSH_PRIVATE_KEY"},
			},
			&cli.StringFlag{
				Name:    "private-key-secret",
				Aliases: []string{},
				Usage:   "server private key secret",
				EnvVars: []string{"SSH_PRIVATE_KEY_SECRET"},
			},
			&cli.StringFlag{
				Name:    "known-hosts",
				Aliases: []string{},
				Usage:   "the known host file path",
				EnvVars: []string{"SSH_KNOWN_HOSTS"},
				Value:   fs.JoinPath(homeDir, ".ssh/known_hosts"),
			},
			&cli.BoolFlag{
				Name:    "ignore-strict-host-key-checking",
				Aliases: []string{},
				Usage:   "whether ignore strict host key checking",
				EnvVars: []string{"SSH_IGNORE_STRICT_HOST_KEY_CHECKING"},
			},
			&cli.StringFlag{
				Name:    "open-in-browser",
				Aliases: []string{},
				Usage:   "open terminal in browser, Example: 127.0.0.1:9000",
				EnvVars: []string{"SSH_OPEN_IN_BROWSER"},
			},
			&cli.StringFlag{
				Name:    "command",
				Aliases: []string{"c"},
				Usage:   "command to execute",
				EnvVars: []string{"SSH_COMMAND"},
			},
		},
		Action: func(ctx *cli.Context) (err error) {
			PrivateKey := ""
			if ctx.String("private-key") != "" && fs.IsExist(ctx.String("private-key")) {
				PrivateKey, err = fs.ReadFileAsString(ctx.String("private-key"))
				if err != nil {
					return fmt.Errorf("failed to read private key: %v", err)
				}
			}

			c := &client.Client{
				Host:                          ctx.String("host"),
				Port:                          ctx.Int("port"),
				User:                          ctx.String("user"),
				Pass:                          ctx.String("pass"),
				PrivateKey:                    PrivateKey,
				PrivateKeySecret:              ctx.String("private-key-secret"),
				KnowHostsFilePath:             ctx.String("known-hosts"),
				IsIgnoreStrictHostKeyChecking: ctx.Bool("ignore-strict-host-key-checking"),
				OpenInBrowserAddress:          ctx.String("open-in-browser"),
				Command:                       ctx.String("command"),
			}

			return c.Connect()
		},
	})
}
