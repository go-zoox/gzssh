package server

import (
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
)

func (s *Server) runInHost(session ssh.Session) (int, error) {
	ptyReq, windowCh, isPty := session.Pty()
	user := session.User()
	var auditor *Auditor
	if s.auditor != nil {
		auditor = s.auditor(user, isPty)
	}

	// 1. interfactive
	if isPty {
		cmd := exec.Command(s.Shell)

		for k, v := range s.Environment {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		cmd.Env = append(cmd.Env, fmt.Sprintf("EXECUTE_USER=%s", user))

		f, err := pty.Start(cmd)
		if err != nil {
			return 1, err
		}

		go func() {
			for window := range windowCh {
				setWindowSize(f, window.Width, window.Height)
			}
		}()

		var writers io.Writer
		if auditor != nil {
			writers = io.MultiWriter(f, auditor)
		} else {
			writers = f
		}
		go io.Copy(writers, session) // stdin
		go io.Copy(session, f)       // stdout

		cmd.Wait()
		return cmd.ProcessState.ExitCode(), nil
	}

	// 2. non-interactive => No PTY Requested

	// 2.1 run command
	commands := session.Command()
	if len(commands) != 0 {
		if auditor != nil {
			for _, c := range commands {
				auditor.Write(append([]byte(c), ' '))
			}

			auditor.Write([]byte{'\r'})
		}

		cmd := exec.Command("sh", "-c", strings.Join(commands, " "))
		for k, v := range s.Environment {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = append(cmd.Env, fmt.Sprintf("EXECUTE_USER=%s", session.User()))

		output, err := cmd.CombinedOutput()
		if err != nil {
			io.WriteString(session, err.Error()+"\n")
			return cmd.ProcessState.ExitCode(), err
		}

		io.WriteString(session, string(output)+"\n")
		return cmd.ProcessState.ExitCode(), nil
	}

	// 2.2 Disable pseudo-terminal allocation.
	io.WriteString(session, fmt.Sprintf("Hi %s! You've successfully authenticated with %s.\n", session.User(), s.BrandName))
	return 0, nil
}
