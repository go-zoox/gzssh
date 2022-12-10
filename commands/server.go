package commands

import (
	"github.com/go-zoox/cli"
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
			&cli.StringFlag{
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
		},
		Action: func(ctx *cli.Context) error {
			s := &server.Server{
				Host: ctx.String("host"),
				Port: ctx.Int("port"),
				OnAuthentication: func(user, pass string) bool {
					return ctx.String("user") == user && ctx.String("pass") == pass
				},
			}

			return s.Start()
		},
	})
}
