package commands

import (
	"fmt"
	"io/ioutil"

	"github.com/go-zoox/cli"
	"github.com/go-zoox/fs"
	"github.com/go-zoox/gzssh/server"
)

func RegistryServer(app *cli.MultipleProgram) {
	app.Register("server", &cli.Command{
		Name:  "server",
		Usage: "start a ssh server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "host",
				Usage:   "server host",
				EnvVars: []string{"HOST"},
			},
			&cli.IntFlag{
				Name:    "port",
				Usage:   "server port",
				Aliases: []string{"p"},
				EnvVars: []string{"PORT"},
			},
			&cli.StringFlag{
				Name:    "user",
				Usage:   "server user",
				Aliases: []string{"u"},
				EnvVars: []string{"USER"},
			},
			&cli.StringFlag{
				Name:    "pass",
				Usage:   "server pass",
				EnvVars: []string{"PASS"},
			},
			&cli.BoolFlag{
				Name:    "run-in-container",
				Usage:   "should run user session in container",
				Aliases: []string{},
				EnvVars: []string{"RUN_IN_CONTAINER"},
				Value:   false,
			},
			&cli.StringFlag{
				Name:    "container-image",
				Usage:   "the container image",
				Aliases: []string{},
				EnvVars: []string{"CONTAINER_IMAGE"},
				Value:   "whatwewant/zmicro:v1",
			},
			&cli.StringFlag{
				Name:    "private-key",
				Usage:   "the server private key, which is privakey key, used for sign host key",
				Aliases: []string{},
				EnvVars: []string{"PRIVATE_KEY"},
			},
			&cli.StringFlag{
				Name:    "private-key-path",
				Usage:   "the filepath of server private key",
				Aliases: []string{},
				EnvVars: []string{"PRIVATE_KEY_PATH"},
			},
			&cli.StringFlag{
				Name:    "authorized-key",
				Usage:   "the authorized key, which is public key, used for verify client",
				Aliases: []string{},
				EnvVars: []string{"AUTHORIZED_KEY"},
			},
			&cli.StringFlag{
				Name:    "authorized-key-path",
				Usage:   "the filepath of authorized key, which is public key",
				Aliases: []string{},
				EnvVars: []string{"AUTHORIZED_KEY_PATH"},
			},
			&cli.BoolFlag{
				Name:    "disable-pty",
				Usage:   "not allow pty request",
				Aliases: []string{},
				EnvVars: []string{"DISABLED_PTY"},
			},
			&cli.StringFlag{
				Name:    "brand-name",
				Usage:   "set brand name, such as welcome message",
				Aliases: []string{},
				EnvVars: []string{"BRAND_NAME"},
			},
		},
		Action: func(ctx *cli.Context) error {
			privateKey := ctx.String("private-key")
			privateKeyFilepath := ctx.String("private-key-path")
			if fs.IsExist(privateKeyFilepath) {
				if privateKey == "" {
					pemBytes, err := ioutil.ReadFile(privateKeyFilepath)
					if err != nil {
						return fmt.Errorf("failed to read server private key: %v", err)
					}

					privateKey = string(pemBytes)
				}
			}

			authorizedKey := ctx.String("authorized-key")
			authorizedKeyFilepath := ctx.String("authorized-key-path")
			if fs.IsExist(authorizedKeyFilepath) {
				if authorizedKey == "" {
					pemBytes, err := ioutil.ReadFile(authorizedKeyFilepath)
					if err != nil {
						return fmt.Errorf("failed to read client public key: %v", err)
					}
					authorizedKey = string(pemBytes)
				}
			}

			s := &server.Server{
				Host: ctx.String("host"),
				Port: ctx.Int("port"),
				User: ctx.String("user"),
				Pass: ctx.String("pass"),
				// OnAuthentication: func(user, pass string) bool {
				// 	return ctx.String("user") == user && ctx.String("pass") == pass
				// },
				//
				IsRunInContainer: ctx.Bool("run-in-container"),
				ContainerImage:   ctx.String("container-image"),
				//
				ServerPrivateKey: privateKey,
				//
				ClientAuthorizedKey: authorizedKey,
				//
				IsPtyDisabled: ctx.Bool("disable-pty"),
				//
				BrandName: ctx.String("brand-name"),
			}

			return s.Start()
		},
	})
}
