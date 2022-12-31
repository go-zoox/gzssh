package commands

import (
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
				Usage:   "the private key",
				Aliases: []string{},
				EnvVars: []string{"PRIVATE_KEY"},
			},
			&cli.StringFlag{
				Name:    "private-key-path",
				Usage:   "the filepath of private key",
				Aliases: []string{},
				EnvVars: []string{"PRIVATE_KEY_PATH"},
			},
		},
		Action: func(ctx *cli.Context) error {
			privateKey := ctx.String("private-key")
			privateKeyFilepath := ctx.String("private-key-path")
			if fs.IsExist(privateKeyFilepath) {
				if privateKey == "" {
					pemBytes, err := ioutil.ReadFile(privateKeyFilepath)
					if err != nil {
						return err
					}
					privateKey = string(pemBytes)
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
				HostKeyPEM: privateKey,
			}

			return s.Start()
		},
	})
}
