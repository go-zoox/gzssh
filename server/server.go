package server

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/go-zoox/fetch"
	"github.com/go-zoox/gzssh/server/sftp"
	"github.com/go-zoox/logger"
	gossh "golang.org/x/crypto/ssh"
)

func CreateDefaultOnAuthentication(defaultUser, defaultPass string, isShowUserPass bool) func(remote, version, user, pass string) bool {
	return func(remote, version, user, pass string) bool {
		// logger.Infof("[user: %s][remote: %s] try to connect ...", user, remote)

		isOK := user == defaultUser && pass == defaultPass
		if !isOK {
			if isShowUserPass {
				logger.Infof("[auth: password][user: %s][remote: %s][version: %s] failed to authenticate(user: %s, pass: %s)", user, remote, version, user, pass)
			} else {
				logger.Infof("[auth: password][user: %s][remote: %s][version: %s] failed to authenticate(pass not correct)", user, remote, version)
			}
		} else {
			if isShowUserPass {
				logger.Infof("[auth: password][user: %s][remote: %s][version: %s] succeed to authenticate(user: %s, pass: %s)", user, remote, version, user, pass)
			} else {
				logger.Infof("[auth: password][user: %s][remote: %s][version: %s] succeed to authenticate.", user, remote, version)
			}
		}

		return isOK
	}
}

type Auditor struct {
	io.Writer

	Print func(user string, remote string, isPty bool, command string)

	User string

	Remote string

	IsPty bool

	buf []byte
}

func (a *Auditor) Write(p []byte) (n int, err error) {
	// fmt.Println(p)

	for _, b := range p {
		// enter '\r'
		if b == 13 {
			command := strings.TrimSpace(string(a.buf))
			if len(command) != 0 {
				a.Print(a.User, a.Remote, a.IsPty, command)
			}

			a.buf = nil
			continue
		}

		// delete
		if b == 127 {
			if len(a.buf)-2 < 0 {
				a.buf = nil
			} else {
				a.buf = a.buf[:len(a.buf)-2]
			}
		} else if b == 9 {
			// tab
		} else {
			a.buf = append(a.buf, b)
		}
	}

	return len(p), nil
}

func CreateDefaultAuditor(auditFn func(user string, remote string, isPty bool, command string)) func(user string, remote string, isPty bool) *Auditor {
	return func(user string, remote string, isPty bool) *Auditor {
		return &Auditor{
			Print:  auditFn,
			User:   user,
			Remote: remote,
			IsPty:  isPty,
		}
	}
}

type Server struct {
	Host        string
	Port        int
	Shell       string
	Environment map[string]string
	// IdleTimeout, unit: seconds
	IdleTimeout int
	// MaxTimeout, unit: seconds
	MaxTimeout int
	//
	OnAuthentication func(remote, version, user, pass string) bool
	OnAudit          func(user string, remote string, isPty bool, command string)
	//
	User string
	Pass string

	//
	IsRunInContainer bool
	// cleanup container => 1. destroy container / 2. stop container
	IsContainerAutoCleanupWhenExitDisabled bool
	// destory container based on cleanup
	IsContainerAutoRemoveWhenExitDisabled bool
	IsContainerRecoveryAllowed            bool
	IsContainerRecoveryDisabled           bool
	// ContainerMaxAge is when container recovery is allowed, recoveried container max age
	//  unit: seconds, default: 3600 (1h)
	ContainerMaxAge int
	WorkDir         string
	// Container Image
	Image string
	// Container Image Registry User
	ImageRegistryUser string
	// Container Image Registry Pass
	ImageRegistryPass string

	// ServerPrivateKey is the server private key for sign host key
	//  also named HostKey PEM
	ServerPrivateKey string

	// ClientAuthorizedKey is the client public key for client authorized
	//  also named Authorized Key
	ClientAuthorizedKey string

	// IsPtyDisabled is pty disabled
	IsPtyDisabled bool

	// BrandName is brand name for welcome message
	BrandName string

	// AuthServer is used for verify user/pass, instead of user/pass
	AuthServer string

	// Version is the GzSSH Version
	Version string

	// ServerEchoVersion is the ssh server echo version, prefix with SSH-2.0-
	//	such as
	//		MacOS 13 => OpenSSH_8.6 (full: SSH-2.0-OpenSSH_8.6)
	//		Ubuntu 22.04 => OpenSSH_8.2p1 Ubuntu-4ubuntu0.4 (full: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4)
	ServerEchoVersion string

	// IsMasqueradeAsOpenSSH will set Server Echo Version as OpenSSH if ServerEchoVersion not set
	IsMasqueradeAsOpenSSH bool

	//
	IsAllowSFTP bool

	//
	IsAllowRemoteForward bool

	//
	IsAllowAudit bool

	// IsHoneypot works as a honey pot
	IsHoneypot             bool
	IsHoneypotAllowAllUser bool
	//
	HoneypotUser string
	HoneypotUID  int
	HoneypotGID  int

	// Resource LIMIT
	// Memory is the memory limit for container, such as 100MB = 100M, 1GB=1G
	Memory string
	// CPUCount  is the cpu core count limit for container, such as 1, 2
	CPUCount int
	// CPUCount  is the cpu percent limit for container, range: 1~100, such as 10, 80
	CPUPercent int

	//
	auditor func(user string, remote string, isPty bool) *Auditor
}

func (s *Server) Start() error {
	if s.BrandName == "" {
		s.BrandName = "GZSSH"
	}

	if s.Shell == "" {
		s.Shell = os.Getenv("SHELL")
		if s.Shell == "" {
			s.Shell = "sh"
		}
	}

	if s.IdleTimeout == 0 {
		s.IdleTimeout = 60
	}

	if s.Environment == nil {
		s.Environment = map[string]string{}
	}
	s.Environment["SERVER_BRAND_TYPE_NAME"] = "GZSSH"
	s.Environment["SERVER_BRAND_TYPE_VERSION"] = s.Version
	s.Environment["SERVER_BRAND_NAME"] = s.BrandName
	if s.IsRunInContainer {
		s.Environment["SERVER_RUN_CONTEXT"] = "CONTAINER"
	} else {
		s.Environment["SERVER_RUN_CONTEXT"] = "HOST"
	}

	if s.OnAuthentication == nil {
		s.OnAuthentication = CreateDefaultOnAuthentication(s.User, s.Pass, s.IsHoneypot)
	}

	options := []ssh.Option{
		ssh.Option(func(server *ssh.Server) error {
			if server.Version == "" {
				if s.IsHoneypot {
					s.IsMasqueradeAsOpenSSH = true
				}

				if s.ServerEchoVersion == "" && s.IsMasqueradeAsOpenSSH {
					s.ServerEchoVersion = "OpenSSH_8.2p1 Ubuntu-4ubuntu0.4"
				}

				if s.ServerEchoVersion == "" {
					s.ServerEchoVersion = fmt.Sprintf("GzSSH_%s", s.Version)
				}

				server.Version = s.ServerEchoVersion
			}

			server.ServerConfigCallback = func(ctx ssh.Context) *gossh.ServerConfig {
				cfg := &gossh.ServerConfig{}

				// cfg.ServerVersion = "SSH-2.0-OpenSSH_8.6"

				return cfg
			}

			// idle timeout
			server.IdleTimeout = time.Duration(s.IdleTimeout) * time.Second

			if s.MaxTimeout != 0 {
				server.MaxTimeout = time.Duration(s.MaxTimeout) * time.Second
			} else if server.MaxTimeout == 0 && s.IsHoneypot {
				server.MaxTimeout = 5 * time.Minute
			}

			// connection
			// connection start
			server.ConnCallback = func(ctx ssh.Context, conn net.Conn) net.Conn {
				logger.Infof("[connection][remote: %s] start to connect ...", conn.RemoteAddr())
				return conn
			}
			// connected failed
			server.ConnectionFailedCallback = func(conn net.Conn, err error) {
				logger.Infof("[connection][remote: %s] failed to connect (err: %s).", conn.RemoteAddr(), err)
			}

			// default not allow login
			server.PasswordHandler = func(ctx ssh.Context, password string) bool {
				return false
			}
			server.PublicKeyHandler = func(ctx ssh.Context, key ssh.PublicKey) bool {
				return false
			}

			return nil
		}),
	}

	// if honeypot, force run in container, avoid being attack.
	if s.IsHoneypot {
		s.IsRunInContainer = true
		s.IsContainerAutoRemoveWhenExitDisabled = true
		// s.IsContainerAllowRecovery = true
		s.IsAllowAudit = true

		if s.IsHoneypotAllowAllUser {
			options = append(options, ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
				logger.Infof("[auth: password] honeypot user %s ...", ctx.User())
				logger.Infof("[auth: password][user: %s][remote %s][version: %s] (user: %s, pass: %s)...", ctx.User(), ctx.RemoteAddr().String(), ctx.ClientVersion(), ctx.User(), pass)
				return true
			}))
		}
	}

	if s.IsContainerRecoveryDisabled {
		s.IsContainerRecoveryAllowed = false
	}

	if s.IsAllowAudit {
		if s.OnAudit == nil {
			s.OnAudit = func(user string, remote string, isPty bool, command string) {
				logger.Infof("[audit][user: %s][remote: %s][pty: %v] %s", user, remote, isPty, command)
			}
		}
	}

	if s.OnAudit != nil {
		s.auditor = CreateDefaultAuditor(s.OnAudit)
	}

	ssh.Handle(func(session ssh.Session) {
		var err error
		user := session.User()
		remote := session.RemoteAddr().String()
		exitCode := 0

		logger.Infof("[handle][user: %s][remote: %s] connected ...", user, remote)

		if s.IsRunInContainer {
			exitCode, err = s.runInContainer(session)
		} else {
			exitCode, err = s.runInHost(session)
		}

		if err != nil {
			logger.Infof("[handle][user: %s][remote: %s] exit(code: %d, error: %s).", user, remote, exitCode, err)
		} else {
			logger.Infof("[handle][user: %s][remote: %s] exit(code: %d).", user, remote, exitCode)
		}

		session.Exit(exitCode)
	})

	if s.User != "" && s.Pass != "" {
		options = append(options, ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
			return s.OnAuthentication(ctx.RemoteAddr().String(), ctx.ClientVersion(), ctx.User(), pass)
		}))
	} else if s.AuthServer != "" {
		options = append(options, ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
			url := fmt.Sprintf("%s/login", s.AuthServer)
			remote := ctx.RemoteAddr().String()
			user := ctx.User()

			response, err := fetch.Post(url, &fetch.Config{
				Headers: map[string]string{
					"content-type": "application/json",
					"accept":       "application/json",
					"user-agent":   fmt.Sprintf("gzssh/%s go-zoox_fetch/%s", s.Version, fetch.Version),
				},
				Body: map[string]string{
					"from":     "gzssh",
					"remote":   remote,
					"username": user,
					"password": pass,
				},
			})
			if err != nil {
				logger.Errorf("failed to login with user(%s) to %s (err: %v)", user, url, err)
				return false
			}

			if !response.Ok() {
				logger.Errorf("failed to login with user(%s) to %s (status: %d, response: %s)", user, url, response.Status, response.String())
				return false
			}

			logger.Infof("[auth: auth_server][user: %s] succeed to authenticate with auth server(%s).", user, s.AuthServer)
			return true
		}))
	}

	if s.ClientAuthorizedKey != "" {
		// https://stackoverflow.com/questions/62236441/getting-ssh-short-read-error-when-trying-to-parse-a-public-key-in-golang
		authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.ClientAuthorizedKey))
		if err != nil {
			return err
		}

		publicKeyPEM, err := ssh.ParsePublicKey(authorizedKey.Marshal())
		if err != nil {
			return err
		}

		options = append(options, ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			// allow all keys
			// return true

			// or use ssh.KeysEqual() to compare against known keys
			remote := ctx.RemoteAddr()
			user := ctx.User()
			isOK := ssh.KeysEqual(key, publicKeyPEM)
			if !isOK {
				logger.Infof("[auth: pubkey][user: %s][remote: %s][version: %s] failed to authenticate.", user, remote, ctx.ClientVersion())
			} else {
				logger.Infof("[auth: pubkey][user: %s][remote: %s][version: %s] succeed to authenticate.", user, remote, ctx.ClientVersion())
			}

			return isOK
		}))
	}

	if s.ServerPrivateKey != "" {
		options = append(options, ssh.HostKeyPEM([]byte(s.ServerPrivateKey)))
	}

	if s.IsPtyDisabled {
		options = append(options, ssh.NoPty())
	}

	if s.IsAllowSFTP {
		options = append(options, ssh.Option(func(s *ssh.Server) error {
			if s.SubsystemHandlers == nil {
				s.SubsystemHandlers = map[string]ssh.SubsystemHandler{}
			}

			// sftp
			s.SubsystemHandlers["sftp"] = sftp.CreateSftp()

			return nil
		}))
	}

	if s.IsAllowRemoteForward {
		options = append(options, ssh.Option(func(s *ssh.Server) error {
			forwardHandler := &ssh.ForwardedTCPHandler{}

			s.LocalPortForwardingCallback = ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
				logger.Infof("accepted forward => %s:%d", dhost, dport)
				return true
			})

			s.ReversePortForwardingCallback = ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
				logger.Infof("attempt to bind => %s:%d", host, port)
				return true
			})

			if s.ChannelHandlers == nil {
				s.ChannelHandlers = map[string]ssh.ChannelHandler{}
			}
			s.ChannelHandlers["direct-tcpip"] = ssh.DirectTCPIPHandler
			s.ChannelHandlers["session"] = ssh.DefaultSessionHandler

			if s.RequestHandlers == nil {
				s.RequestHandlers = map[string]ssh.RequestHandler{}
			}
			s.RequestHandlers["tcpip-forward"] = forwardHandler.HandleSSHRequest
			s.RequestHandlers["cancel-tcpip-forward"] = forwardHandler.HandleSSHRequest

			return nil
		}))
	}

	if s.ContainerMaxAge == 0 {
		s.ContainerMaxAge = 3600
	}

	if s.Port == 0 {
		s.Port = 22
	}

	address := fmt.Sprintf("%s:%d", s.Host, s.Port)

	// @TODO echo server info
	options = append(options, func(session *ssh.Server) error {
		logger.Infof("[runtime] brand: %s", s.BrandName)
		logger.Infof("[runtime] gzssh: %s", s.Version)
		logger.Infof("[runtime] server version: SSH-2.0-%s", s.ServerEchoVersion)
		if !s.IsRunInContainer {
			logger.Infof("[runtime] mode: %s", "host")
		} else {
			logger.Infof("[runtime] mode: %s", "container")
			logger.Infof("[runtime] auto cleanup container: %v", !s.IsContainerAutoCleanupWhenExitDisabled)
			logger.Infof("[runtime] auto remove container: %v", !s.IsContainerAutoRemoveWhenExitDisabled)

			logger.Infof("[runtime] container recovery: %v", s.IsContainerRecoveryAllowed)
			if s.IsContainerRecoveryAllowed {
				logger.Infof("[runtime] container max age: %ds", s.ContainerMaxAge)
			}
		}
		if s.WorkDir != "" {
			logger.Infof("[runtime] workdir: %s", s.WorkDir)
		}
		if s.AuthServer != "" {
			logger.Infof("[runtime] auth server: %s", s.AuthServer)
		}

		logger.Infof("[runtime] sftp: %v", s.IsAllowSFTP)
		logger.Infof("[runtime] remote port forward: %v", s.IsAllowRemoteForward)
		logger.Infof("[runtime] audit: %v", s.IsAllowAudit)

		if s.Memory != "" {
			logger.Infof("[runtime] memory: %s", s.Memory)
		}
		if s.CPUCount != 0 {
			logger.Infof("[runtime] cpu: %d", s.CPUCount)
		}
		if s.CPUPercent != 0 {
			logger.Infof("[runtime] cpu percent: %d", s.CPUPercent)
		}
		if s.IsHoneypot {
			logger.Infof("[runtime] honeypot: %v", true)
		}

		logger.Infof("[runtime] starting ssh server at: %s ...", address)
		return nil
	})

	return ssh.ListenAndServe(address, nil, options...)
}
