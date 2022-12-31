package server

import (
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
)

func (s *Server) runInHost(session ssh.Session) {
	ptyReq, windowCh, isPty := session.Pty()

	// 1. interfactive
	if isPty {
		cmd := exec.Command(s.Shell)

		for k, v := range s.Environment {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		cmd.Env = append(cmd.Env, fmt.Sprintf("EXECUTE_USER=%s", session.User()))

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
		return
	}

	// 2. non-interactive => No PTY Requested

	// 2.1 run command
	commands := session.Command()
	if len(commands) != 0 {
		cmd := exec.Command("sh", "-c", strings.Join(commands, "\n"))
		for k, v := range s.Environment {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = append(cmd.Env, fmt.Sprintf("EXECUTE_USER=%s", session.User()))

		output, err := cmd.CombinedOutput()
		if err != nil {
			io.WriteString(session, err.Error()+"\n")
			session.Exit(1)
			return
		}

		io.WriteString(session, string(output)+"\n")
		session.Exit(0)
		return
	}

	// 2.2 Disable pseudo-terminal allocation.
	io.WriteString(session, fmt.Sprintf("Hi %s! You've successfully authenticated with %s.\n", session.User(), s.BrandName))
	session.Exit(0)
}
