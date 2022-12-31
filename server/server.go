package server

import (
	"fmt"
	"os"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/go-zoox/logger"
)

func CreateDefaultOnAuthentication(defaultUser, defaultPass string) func(user, pass string) bool {
	return func(user, pass string) bool {
		logger.Infof("[user: %s] try to connect ...", user)

		isOK := user == defaultUser && pass == defaultPass
		if !isOK {
			logger.Infof("[user: %s] failed to authenticate.", user)
		} else {
			logger.Infof("[user: %s] succeed to authenticate.", user)
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
	OnAuthentication func(user, pass string) bool
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
}

func (s *Server) Start() error {
	if s.Shell == "" {
		s.Shell = os.Getenv("SHELL")
		if s.Shell == "" {
			s.Shell = "sh"
		}
	}

	if s.IdleTimeout == 0 {
		s.IdleTimeout = 60 * time.Second
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
			server.IdleTimeout = s.IdleTimeout
			return nil
		}),
	}

	if s.User != "" && s.Pass != "" {
		options = append(options, ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
			return s.OnAuthentication(ctx.User(), pass)
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
			user := ctx.User()
			isOK := ssh.KeysEqual(key, publicKeyPEM)
			logger.Infof("[user: %s] try to connect ...", user)
			if !isOK {
				logger.Infof("[user: %s] failed to authenticate.", user)
			} else {
				logger.Infof("[user: %s] succeed to authenticate.", user)
			}

			return isOK
		}))
	}

	if s.ServerPrivateKey != "" {
		options = append(options, ssh.HostKeyPEM([]byte(s.ServerPrivateKey)))
	}

	if s.Port == 0 {
		return fmt.Errorf("port is required")
	}
	address := fmt.Sprintf("%s:%d", s.Host, s.Port)
	logger.Infof("starting ssh server at: %s ...", address)
	return ssh.ListenAndServe(address, nil, options...)
}
