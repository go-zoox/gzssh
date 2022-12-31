package server

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/go-zoox/fetch"
	"github.com/go-zoox/logger"
)

func CreateDefaultOnAuthentication(defaultUser, defaultPass string) func(remote, user, pass string) bool {
	return func(remote, user, pass string) bool {
		logger.Infof("[user: %s][remote: %s] try to connect ...", user, remote)

		isOK := user == defaultUser && pass == defaultPass
		if !isOK {
			logger.Infof("[user: %s][remote: %s] failed to authenticate.", user, remote)
		} else {
			logger.Infof("[user: %s][remote: %s] succeed to authenticate.", user, remote)
		}

		return isOK
	}
}

type Server struct {
	Host        string
	Port        int
	Shell       string
	Environment map[string]string
	IdleTimeout time.Duration
	//
	OnAuthentication func(remote, user, pass string) bool
	//
	User string
	Pass string
	//
	IsRunInContainer bool
	ContainerImage   string

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

	//
	Version string
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
		s.IdleTimeout = 60 * time.Second
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
		s.OnAuthentication = CreateDefaultOnAuthentication(s.User, s.Pass)
	}

	ssh.Handle(func(session ssh.Session) {
		if s.IsRunInContainer {
			s.runInContainer(session)
			return
		}

		s.runInHost(session)
	})

	options := []ssh.Option{
		ssh.Option(func(server *ssh.Server) error {
			// idle timeout
			server.IdleTimeout = s.IdleTimeout

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

			return nil
		}),
	}

	if s.User != "" && s.Pass != "" {
		options = append(options, ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
			return s.OnAuthentication(ctx.RemoteAddr().String(), ctx.User(), pass)
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

			logger.Infof("[user: %s] succeed to authenticate with auth server(%s).", user, s.AuthServer)
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
			logger.Infof("[user: %s][remote: %s] try to connect ...", user, remote)
			if !isOK {
				logger.Infof("[user: %s][remote: %s] failed to authenticate.", user, remote)
			} else {
				logger.Infof("[user: %s][remote: %s] succeed to authenticate.", user, remote)
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

	if s.Port == 0 {
		return fmt.Errorf("port is required")
	}
	address := fmt.Sprintf("%s:%d", s.Host, s.Port)
	logger.Infof("starting ssh server at: %s ...", address)
	return ssh.ListenAndServe(address, nil, options...)
}
