package commands

import (
	"fmt"
	"io/ioutil"
	"os/user"
	"runtime"

	"github.com/go-zoox/cli"
	"github.com/go-zoox/fs"
	"github.com/go-zoox/gzssh/server"
)

var defaultPrivateKeyPath = ""
var defaultAuthroziedKeyPath = ""
var defaultLogDir = "/tmp/log/gzssh"

func init() {
	currentUser, err := user.Current()
	if err == nil {
		if currentUser.Uid == "0" || currentUser.Gid == "0" {
			if fs.IsExist("/etc/ssh/ssh_host_rsa_key") {
				defaultPrivateKeyPath = "/etc/ssh/ssh_host_rsa_key"
			}

			if err := fs.Mkdirp("/var/log/gzssh"); err == nil {
				defaultLogDir = "/var/log/gzssh"
			}
		}
	}

	if fs.IsExist(fs.JoinHomeDir(".ssh/authorized_keys")) {
		defaultAuthroziedKeyPath = fs.JoinHomeDir(".ssh/authorized_keys")
	}
}

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
				Value:   8848,
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
			&cli.StringFlag{
				Name:    "log-dir",
				Usage:   "the log dir for access, auth, and audit",
				Aliases: []string{},
				EnvVars: []string{"LOG_DIR"},
				Value:   defaultLogDir,
			},
			&cli.StringFlag{
				Name:    "startup-command",
				Usage:   "run command from startup, only works in pty",
				EnvVars: []string{"STARTUP_COMMAND"},
			},
			&cli.BoolFlag{
				Name:    "no-write",
				Usage:   "no allow client to input command, only subscribe server response, require startup-command not empty",
				EnvVars: []string{"NO_WRITE"},
			},
			&cli.BoolFlag{
				Name:    "run-in-container",
				Usage:   "should run user session in container",
				Aliases: []string{},
				EnvVars: []string{"RUN_IN_CONTAINER"},
			},
			&cli.BoolFlag{
				Name:    "disable-container-auto-cleanup-when-exit",
				Usage:   "disable container auto cleanup when exit, maybe destroy or stop container, default cleanup strategy is destroy container",
				Aliases: []string{},
				EnvVars: []string{"DISABLE_CONTAINER_AUTO_CLEANUP_WHEN_EXIT"},
			},
			&cli.BoolFlag{
				Name:    "container-auto-destory-immediately-when-exit",
				Usage:   "enable container auto destory immediately when exit",
				Aliases: []string{},
				EnvVars: []string{"CONTAINER_AUTO_DESTROY_IMMEDIATELY_WHEN_EXIT"},
			},
			&cli.BoolFlag{
				Name:    "disable-container-recovery",
				Usage:   "allow container allow recovery for honeypot",
				Aliases: []string{},
				EnvVars: []string{"DISABLED_CONTAINER_RECOVERY"},
			},
			&cli.BoolFlag{
				Name:    "allow-container-privilege",
				Usage:   "Container allow privileged, which equals docker --privileged",
				Aliases: []string{},
				EnvVars: []string{"ALLOW_CONTAINER_PRIVILEGE"},
			},
			&cli.BoolFlag{
				Name:    "container-readonly",
				Usage:   "Container readonly, which equals docker --read-only",
				Aliases: []string{},
				EnvVars: []string{"CONTAINER_READONLY"},
			},
			&cli.StringFlag{
				Name:    "container-readonly-paths",
				Usage:   "container specifys the readonly paths",
				Aliases: []string{},
				EnvVars: []string{"CONTAINER_READONLY_PATHS"},
			},
			&cli.StringFlag{
				Name:    "container-network-mode",
				Usage:   "container specifys the network mode, options: default | none | container:X",
				Aliases: []string{},
				EnvVars: []string{"CONTAINER_NETWORK_MODE"},
			},
			&cli.StringFlag{
				Name:    "container-network",
				Usage:   "container specifys the external network name",
				Aliases: []string{},
				EnvVars: []string{"CONTAINER_NETWORK"},
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
				Aliases: []string{"work-dir"},
				EnvVars: []string{"WORKDIR"},
			},
			&cli.StringFlag{
				Name:    "permission-dir",
				Usage:   "the permission dir, which must be based on workdir",
				EnvVars: []string{"PERMISSION_DIR"},
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
				Value:   defaultPrivateKeyPath,
			},
			&cli.StringFlag{
				Name:    "authorized-key",
				Usage:   "the authorized key, which is public key, used for verify client",
				Aliases: []string{},
				EnvVars: []string{"AUTHORIZED_KEY"},
			},
			&cli.StringFlag{
				Name:    "authorized-keys-path",
				Usage:   "the filepath of authorized key, which is public key",
				Aliases: []string{},
				EnvVars: []string{"AUTHORIZED_KEY_PATH"},
				Value:   defaultAuthroziedKeyPath,
			},
			&cli.BoolFlag{
				Name:    "disable-pty",
				Usage:   "not allow pty request",
				Aliases: []string{},
				EnvVars: []string{"DISABLED_PTY"},
			},
			&cli.StringFlag{
				Name:    "brand-name",
				Usage:   "set brand name for welcome message",
				Aliases: []string{},
				EnvVars: []string{"BRAND_NAME"},
			},
			&cli.StringFlag{
				Name:    "banner",
				Usage:   "set banner, which is the welcome message",
				Aliases: []string{},
				EnvVars: []string{"BANNER"},
			},
			&cli.StringFlag{
				Name:    "auth-server",
				Usage:   "auth server for verify user/pass, instead of user/pass",
				Aliases: []string{},
				EnvVars: []string{"AUTH_SERVER"},
			},
			&cli.BoolFlag{
				Name:    "qrcode",
				Usage:   "qrcode login, works with auth-server, if qrcode is true, auth-server(default: https://login.zcorky.com) is the qrcode oauth server",
				Aliases: []string{},
				EnvVars: []string{"QRCODE"},
			},
			&cli.StringFlag{
				Name:    "qrcode-client-id",
				Usage:   "the oauth server (auth-server) client id",
				Aliases: []string{},
				EnvVars: []string{"QRCODE_CLIENT_ID"},
			},
			&cli.StringFlag{
				Name:    "qrcode-redirect-uri",
				Usage:   "the oauth server (auth-server) redirect uri",
				Aliases: []string{},
				EnvVars: []string{"QRCODE_REDIRECT_URI"},
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
				Name:    "audit",
				Usage:   "open audit",
				Aliases: []string{},
				EnvVars: []string{"AUDIT"},
			},
			&cli.StringFlag{
				Name:    "audit-log-dir",
				Usage:   "the log file to write audit",
				Aliases: []string{},
				EnvVars: []string{"AUDIT_LOG_DIR"},
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
			&cli.Float64Flag{
				Name:    "cpus",
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
			&cli.BoolFlag{
				Name:    "no-history",
				Usage:   "Ignore Command History",
				Aliases: []string{},
				EnvVars: []string{"NO_HISTORY"},
			},
			&cli.StringFlag{
				Name:    "shell",
				Usage:   "cusom shell",
				Aliases: []string{},
				EnvVars: []string{"CUSTOM_SHELL"},
			},
			&cli.BoolFlag{
				Name:    "disable-root-login",
				Usage:   "Disable root login",
				Aliases: []string{},
				EnvVars: []string{"DISABLE_ROOT_LOGIN"},
			},
		},
		Action: func(ctx *cli.Context) error {
			privateKey := ctx.String("private-key")
			privateKeyFilepath := ctx.String("private-key-path")
			if privateKeyFilepath != "" {
				if !fs.IsExist(privateKeyFilepath) {
					return fmt.Errorf("private key file(%s) not found", privateKeyFilepath)
				}

				if privateKey == "" {
					pemBytes, err := ioutil.ReadFile(privateKeyFilepath)
					if err != nil {
						return fmt.Errorf("failed to read server private key: %v", err)
					}

					privateKey = string(pemBytes)
				}
			}

			authorizedKeys := []string{}
			if ctx.String("authorized-key") != "" {
				authorizedKeys = append(authorizedKeys, ctx.String("authorized-key"))
			}
			authorizedKeyFilepath := ctx.String("authorized-keys-path")
			if fs.IsExist(authorizedKeyFilepath) {
				// if authorizedKey == "" {
				// 	pemBytes, err := ioutil.ReadFile(authorizedKeyFilepath)
				// 	if err != nil {
				// 		return fmt.Errorf("failed to read client public key: %v", err)
				// 	}
				// 	authorizedKey = string(pemBytes)
				// }
				lines, err := fs.ReadFileLines(authorizedKeyFilepath)
				if err != nil {
					return fmt.Errorf("failed to read authorized keys(%s): %v", authorizedKeyFilepath, err)
				}
				authorizedKeys = append(authorizedKeys, lines...)
			}

			//
			cpus := ctx.Float64("cpus")
			if cpus < 0 {
				cpus = float64(runtime.NumCPU())
			}

			s := &server.Server{
				Host: ctx.String("host"),
				Port: ctx.Int("port"),
				User: ctx.String("user"),
				Pass: ctx.String("pass"),
				//
				LogDir: ctx.String("log-dir"),
				// startup
				StartupCommand:        ctx.String("startup-command"),
				IsNotAllowClientWrite: ctx.Bool("no-write"),
				// OnAuthentication: func(user, pass string) bool {
				// 	return ctx.String("user") == user && ctx.String("pass") == pass
				// },
				//
				IsRunInContainer:                          ctx.Bool("run-in-container"),
				IsContainerAutoCleanupWhenExitDisabled:    ctx.Bool("disable-container-auto-cleanup-when-exit"),
				IsContainerAutoDestroyImmediatelyWhenExit: ctx.Bool("container-auto-destory-immediately-when-exit"),
				IsContainerRecoveryDisabled:               ctx.Bool("disable-container-recovery"),
				IsContainerPrivilegeAllowed:               ctx.Bool("allow-container-privilege"),
				IsContainerReadonly:                       ctx.Bool("container-readonly"),
				ContainerReadonlyPaths:                    ctx.String("container-readonly-paths"),
				ContainerNetworkMode:                      ctx.String("container-network-mode"),
				ContainerNetwork:                          ctx.String("container-network"),
				ContainerMaxAge:                           ctx.Int("container-max-age"),
				WorkDir:                                   ctx.String("workdir"),
				PermissionDir:                             ctx.String("permission-dir"),
				Image:                                     ctx.String("image"),
				ImageRegistryUser:                         ctx.String("image-registry-user"),
				ImageRegistryPass:                         ctx.String("image-registry-pass"),
				//
				ServerPrivateKey: privateKey,
				//
				ClientAuthorizedKeys: authorizedKeys,
				//
				IsPtyDisabled: ctx.Bool("disable-pty"),
				//
				BrandName: ctx.String("brand-name"),
				Banner:    ctx.String("banner"),
				//
				AuthServer:        ctx.String("auth-server"),
				QRCode:            ctx.Bool("qrcode"),
				QRCodeClientID:    ctx.String("qrcode-client-id"),
				QRCodeRedirectURI: ctx.String("qrcode-redirect-uri"),
				//
				Version: ctx.App.Version,
				//
				IsAllowSFTP: ctx.Bool("allow-sftp"),
				//
				IsAllowRemoteForward: ctx.Bool("allow-remote-forward"),
				//
				IsAllowAudit: ctx.Bool("audit"),
				AuditLogDir:  ctx.String("audit-log-dir"),
				//
				IsHoneypot:             ctx.Bool("honeypot"),
				IsHoneypotAllowAllUser: ctx.Bool("honeypot-allow-all-user"),
				HoneypotUID:            ctx.Int("honeypot-uid"),
				HoneypotGID:            ctx.Int("honeypot-gid"),
				HoneypotUser:           ctx.String("honeypot-user"),
				//
				Memory:     ctx.String("memory"),
				CPUs:       cpus,
				CPUPercent: ctx.Int("cpu-percent"),
				CpusetCpus: ctx.String("cpuset-cpus"),
				CpusetMems: ctx.String("cpuset-mems"),
				//
				IdleTimeout: ctx.Int("idle-timeout"),
				MaxTimeout:  ctx.Int("max-timeout"),
				//
				ServerEchoVersion: ctx.String("server-echo-version"),
				//
				IsMasqueradeAsOpenSSH: ctx.Bool("masquerade-as-openssh"),
				//
				IsNoHistory: ctx.Bool("no-history"),
				//
				Shell: ctx.String("shell"),
				//
				IsRootLoginDisabled: ctx.Bool("disable-root-login"),
			}

			return s.Start()
		},
	})
}
