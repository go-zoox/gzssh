package server

import (
	"fmt"
	"net"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/go-zoox/fetch"
	"github.com/go-zoox/gzssh/server/sftp"
	"github.com/go-zoox/logger"
	gossh "golang.org/x/crypto/ssh"
)

func (s *Server) Options() ([]ssh.Option, error) {
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

	if s.IsHoneypotAllowAllUser {
		options = append(options, ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
			logger.Infof("[auth: password] honeypot user %s ...", ctx.User())
			logger.Infof("[auth: password][user: %s][remote %s][version: %s] (user: %s, pass: %s)...", ctx.User(), ctx.RemoteAddr().String(), ctx.ClientVersion(), ctx.User(), pass)

			if err := s.setSessionUser(ctx.SessionID(), "password", ctx.User(), pass, ""); err != nil {
				logger.Errorf("failed to setSessionUser (session id: %s, user: %s): %s", ctx.SessionID(), ctx.User(), err)
				return false
			}

			return true
		}))
	}

	if s.User != "" && s.Pass != "" {
		options = append(options, ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
			user := ctx.User()
			if s.IsRootLoginDisabled && user == "root" {
				return false
			}

			ok := s.OnAuthentication(ctx.RemoteAddr().String(), ctx.ClientVersion(), user, pass)
			if !ok {
				return false
			}

			if err := s.setSessionUser(ctx.SessionID(), "password", user, pass, ""); err != nil {
				logger.Errorf("failed to setSessionUser (2) (session id: %s, user: %s): %s", ctx.SessionID(), user, err)
				return false
			}
			return true
		}))
	} else if s.AuthServer != "" {
		// qrcode login
		if s.QRCode {
			if s.QRCodeClientID == "" || s.QRCodeRedirectURI == "" {
				return nil, fmt.Errorf("[qrcode] client id (--qrcode-client-id) and redirect uri (--qrcode-redirect-uri) are required")
			}

			options = append(options, func(s *ssh.Server) error {
				originServerConfigCallback := s.ServerConfigCallback

				s.ServerConfigCallback = func(ctx ssh.Context) *gossh.ServerConfig {
					var cfg *gossh.ServerConfig
					if originServerConfigCallback == nil {
						cfg = &gossh.ServerConfig{}
					} else {
						cfg = originServerConfigCallback(ctx)
					}

					cfg.NoClientAuth = true

					// fmt.Println("cfg.NoClientAuth:", cfg.NoClientAuth)

					return cfg
				}

				return nil
			})
		} else {
			// password login
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

				if err := s.setSessionUser(ctx.SessionID(), "password", ctx.User(), pass, ""); err != nil {
					logger.Errorf("failed to setSessionUser (2) (session id: %s, user: %s): %s", ctx.SessionID(), ctx.User(), err)
					return false
				}

				return true
			}))
		}
	} else {
		if s.QRCode {
			return nil, fmt.Errorf("[qrcode] require --auth-server as qrcode oauth server")
		}
	}

	if s.ClientAuthorizedKey != "" {
		// https://stackoverflow.com/questions/62236441/getting-ssh-short-read-error-when-trying-to-parse-a-public-key-in-golang
		authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.ClientAuthorizedKey))
		if err != nil {
			return nil, err
		}

		publicKeyPEM, err := ssh.ParsePublicKey(authorizedKey.Marshal())
		if err != nil {
			return nil, err
		}

		options = append(options, ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			// allow all keys
			// return true

			// or use ssh.KeysEqual() to compare against known keys
			remote := ctx.RemoteAddr()
			user := ctx.User()
			if s.IsRootLoginDisabled && user == "root" {
				return false
			}

			isOK := ssh.KeysEqual(key, publicKeyPEM)
			if !isOK {
				logger.Infof("[auth: pubkey][user: %s][remote: %s][version: %s] failed to authenticate.", user, remote, ctx.ClientVersion())
				return false
			}

			logger.Infof("[auth: pubkey][user: %s][remote: %s][version: %s] succeed to authenticate.", user, remote, ctx.ClientVersion())

			if err := s.setSessionUser(ctx.SessionID(), "password", ctx.User(), string(key.Marshal()), ""); err != nil {
				logger.Errorf("failed to setSessionUser (2) (session id: %s, user: %s): %s", ctx.SessionID(), ctx.User(), err)
				return false
			}

			return true
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

	if s.BannerCallback != nil {
		options = append(options, func(server *ssh.Server) error {
			originServerConfigCallback := server.ServerConfigCallback

			server.ServerConfigCallback = func(ctx ssh.Context) *gossh.ServerConfig {
				var cfg *gossh.ServerConfig
				if originServerConfigCallback == nil {
					cfg = &gossh.ServerConfig{}
				} else {
					cfg = originServerConfigCallback(ctx)
				}

				cfg.BannerCallback = s.BannerCallback

				return cfg
			}

			return nil
		})
	}

	return options, nil
}
