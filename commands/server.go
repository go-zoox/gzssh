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
				Value:   22,
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
			},
			&cli.BoolFlag{
				Name:    "disable-container-auto-remove-when-exit",
				Usage:   "Container auto remove when exit",
				Aliases: []string{},
				EnvVars: []string{"CONTAINER_AUTO_REMOVE_WHEN_EXIT"},
				Value:   true,
			},
			&cli.BoolFlag{
				Name:    "allow-container-recovery",
				Usage:   "Container allow recovery from stopped",
				Aliases: []string{},
				EnvVars: []string{"ALLOW_CONTAINER_RECOVERY"},
			},
			&cli.BoolFlag{
				Name:    "disable-container-recovery",
				Usage:   "allow container allow recovery for honeypot",
				Aliases: []string{},
				EnvVars: []string{"DISABLED_CONTAINER_RECOVERY"},
			},
			&cli.IntFlag{
				Name:    "container-max-age",
				Usage:   "when container recovery is allowed, recoveried container max age, unit: seconds",
				Aliases: []string{},
				EnvVars: []string{"CONTAINER_MAX_AGE"},
				Value:   3600,
			},

			&cli.StringFlag{
				Name:    "image",
				Usage:   "the container image",
				Aliases: []string{},
				EnvVars: []string{"CONTAINER_IMAGE"},
				Value:   "whatwewant/zmicro:v1",
			},
			&cli.StringFlag{
				Name:    "image-registry-user",
				Usage:   "the user for container image registry",
				Aliases: []string{},
				EnvVars: []string{"CONTAINER_IMAGE_REGISTRY_USER"},
			},
			&cli.StringFlag{
				Name:    "image-registry-pass",
				Usage:   "the password for container image registry",
				Aliases: []string{},
				EnvVars: []string{"CONTAINER_IMAGE_REGISTRY_PASS"},
			},
			&cli.StringFlag{
				Name:    "workdir",
				Usage:   "the workdir",
				Aliases: []string{},
				EnvVars: []string{"WORKDIR"},
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
			&cli.StringFlag{
				Name:    "auth-server",
				Usage:   "auth server for verify user/pass, instead of user/pass",
				Aliases: []string{},
				EnvVars: []string{"AUTH_SERVER"},
			},
			&cli.BoolFlag{
				Name:    "allow-sftp",
				Usage:   "allow sftp server",
				Aliases: []string{},
				EnvVars: []string{"ALLOW_SFTP"},
			},
			&cli.BoolFlag{
				Name:    "allow-remote-forward",
				Usage:   "allow remote forward",
				Aliases: []string{},
				EnvVars: []string{"ALLOW_REMOTE_FORWARD"},
			},
			&cli.BoolFlag{
				Name:    "allow-audit",
				Usage:   "allow audit",
				Aliases: []string{},
				EnvVars: []string{"ALLOW_AUDIT"},
			},
			&cli.BoolFlag{
				Name:    "honeypot",
				Usage:   "work as a honey pot",
				Aliases: []string{},
				EnvVars: []string{"HONEYPOT"},
			},
			&cli.BoolFlag{
				Name:    "honeypot-allow-all-user",
				Usage:   "allow user for honeypot",
				Aliases: []string{},
				EnvVars: []string{"HONEYPOT_ALLOW_ALL_USER"},
			},
			&cli.StringFlag{
				Name:    "honeypot-user",
				Usage:   "honeypot username",
				Aliases: []string{},
				EnvVars: []string{"HONEYPOT_USER"},
			},
			&cli.IntFlag{
				Name:    "honeypot-uid",
				Usage:   "honeypot user id",
				Aliases: []string{},
				EnvVars: []string{"HONEYPOT_UID"},
			},
			&cli.IntFlag{
				Name:    "honeypot-gid",
				Usage:   "honeypot group id",
				Aliases: []string{},
				EnvVars: []string{"HONEYPOT_GID"},
			},
			&cli.StringFlag{
				Name:    "memory",
				Usage:   "Max Memory, such as 100M, 1G",
				Aliases: []string{},
				EnvVars: []string{"MEMORY"},
			},
			&cli.IntFlag{
				Name:    "cpu-count",
				Usage:   "Max CPU Core Count, such as 2",
				Aliases: []string{},
				EnvVars: []string{"CPU_COUNT"},
			},
			&cli.IntFlag{
				Name:    "cpu-percent",
				Usage:   "Max CPU Percent, range: 1~99, such as 10",
				Aliases: []string{},
				EnvVars: []string{"CPU_PERCENT"},
			},
			&cli.IntFlag{
				Name:    "idle-timeout",
				Usage:   "idle timeout, unit: seconds, default: 60",
				Aliases: []string{},
				EnvVars: []string{"IDLE_TIMEOUT"},
				Value:   60,
			},
			&cli.IntFlag{
				Name:    "max-timeout",
				Usage:   "max timeout, unit: seconds, no limit, if honeypot, 5 min",
				Aliases: []string{},
				EnvVars: []string{"MAX_TIMEOUT"},
			},
			&cli.StringFlag{
				Name:    "server-echo-version",
				Usage:   "the ssh server echo version, prefix with SSH-2.0-",
				Aliases: []string{},
				EnvVars: []string{"SERVER_ECHO_VERSION"},
			},
			&cli.BoolFlag{
				Name:    "masquerade-as-openssh",
				Usage:   "Masquerade as a openssh server",
				Aliases: []string{},
				EnvVars: []string{"MASQUERADE_AS_OPENSSH"},
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
				IsRunInContainer:                      ctx.Bool("run-in-container"),
				IsContainerAutoRemoveWhenExitDisabled: ctx.Bool("disable-container-auto-remove-when-exit"),
				IsContainerRecoveryAllowed:            ctx.Bool("allow-container-recovery"),
				IsContainerRecoveryDisabled:           ctx.Bool("disable-container-recovery"),
				ContainerMaxAge:                       ctx.Int("container-max-age"),
				WorkDir:                               ctx.String("workdir"),
				Image:                                 ctx.String("image"),
				ImageRegistryUser:                     ctx.String("image-registry-user"),
				ImageRegistryPass:                     ctx.String("image-registry-pass"),
				//
				ServerPrivateKey: privateKey,
				//
				ClientAuthorizedKey: authorizedKey,
				//
				IsPtyDisabled: ctx.Bool("disable-pty"),
				//
				BrandName: ctx.String("brand-name"),
				//
				AuthServer: ctx.String("auth-server"),
				//
				Version: ctx.App.Version,
				//
				IsAllowSFTP: ctx.Bool("allow-sftp"),
				//
				IsAllowRemoteForward: ctx.Bool("allow-remote-forward"),
				//
				IsAllowAudit: ctx.Bool("allow-audit"),
				//
				IsHoneypot:             ctx.Bool("honeypot"),
				IsHoneypotAllowAllUser: ctx.Bool("honeypot-allow-all-user"),
				HoneypotUID:            ctx.Int("honeypot-uid"),
				HoneypotGID:            ctx.Int("honeypot-gid"),
				HoneypotUser:           ctx.String("honeypot-user"),
				//
				Memory:     ctx.String("memory"),
				CPUCount:   ctx.Int("cpu-count"),
				CPUPercent: ctx.Int("cpu-percent"),
				//
				IdleTimeout: ctx.Int("idle-timeout"),
				MaxTimeout:  ctx.Int("max-timeout"),
				//
				ServerEchoVersion: ctx.String("server-echo-version"),
				//
				IsMasqueradeAsOpenSSH: ctx.Bool("masquerade-as-openssh"),
			}

			return s.Start()
		},
	})
}
