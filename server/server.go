package server

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
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
}

func setWindowSize(f *os.File, w, h int) {
	syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})),
	)
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
		cmd := exec.Command(s.Shell)
		ptyReq, windowCh, isPty := session.Pty()
		if isPty {
			cmd.Env = append(
				cmd.Env,
				fmt.Sprintf("TERM=%s", ptyReq.Term),
			)
			f, err := pty.Start(cmd)
			if err != nil {
				panic(err)
			}

			go func() {
				for window := range windowCh {
					setWindowSize(f, window.Width, window.Height)
				}
			}()

			go io.Copy(f, session) // stdin
			go io.Copy(session, f) // stdout

			cmd.Wait()
		} else {
			io.WriteString(session, "No PTY Requested.\n")
			session.Exit(1)
		}
	})

	options := []ssh.Option{
		ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
			return s.OnAuthentication(ctx.User(), pass)
		}),
		// ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
		// 	// allow all keys
		// 	return true
		// 	// or use ssh.KeysEqual() to compare against known keys
		// 	// return ssh.KeysEqual()
		// }),
		ssh.Option(func(server *ssh.Server) error {
			server.IdleTimeout = s.IdleTimeout
			return nil
		}),
	}

	if s.Port == 0 {
		return fmt.Errorf("port is required")
	}
	address := fmt.Sprintf("%s:%d", s.Host, s.Port)
	logger.Infof("starting ssh server at: %s ...", address)
	return ssh.ListenAndServe(address, nil, options...)
}
