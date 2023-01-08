package server

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
)

func (s *Server) runInHost(session ssh.Session) (int, int, error) {
	if s.Shell == "" {
		s.Shell = os.Getenv("SHELL")
		if s.Shell == "" {
			s.Shell = "sh"
		}
	}

	if s.PermissionDir != "" {
		if s.WorkDir == "" {
			return -1, 400100, fmt.Errorf("if use permission dir, work dir is required")
		}
	}

	if !strings.HasPrefix(s.WorkDir, s.PermissionDir) {
		return -1, 400101, fmt.Errorf("permission dir(%s) must based on work dir(%s)", s.PermissionDir, s.WorkDir)
	}

	ptyReq, windowCh, isPty := session.Pty()
	user := session.User()
	remote := session.RemoteAddr().String()
	var auditor *Auditor
	if s.auditor != nil {
		auditor = s.auditor(user, remote, isPty)
	}

	// 1. interfactive
	if isPty {
		var cmd *exec.Cmd

		commands := []string{}
		if isPty {
			if s.StartupCommand != "" {
				commands = append(commands, s.StartupCommand)

				if !s.IsNotAllowClientWrite {
					// mergedCommand = fmt.Sprintf("%s && %s", s.StartupCommand, s.Shell)
					commands = append(commands, s.Shell)
				}
			}
		} else {
			sessionCommands := session.Command()
			if len(sessionCommands) != 0 {
				mergedSessionCommand := strings.Join(sessionCommands, " ")
				commands = append(commands, mergedSessionCommand)

				auditor.Write([]byte(mergedSessionCommand + "\r"))
			}
		}

		if len(commands) != 0 {
			cmd = exec.Command("sh", "-c", strings.Join(commands, " && "))
		} else {
			cmd = exec.Command(s.Shell)
		}

		for k, v := range s.Environment {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		cmd.Env = append(cmd.Env, fmt.Sprintf("EXECUTE_USER=%s", user))

		if s.WorkDir == "" {
			homedir, err := os.UserHomeDir()
			if err != nil {
				return -1, 400102, err
			}

			cmd.Dir = homedir
		}

		cmd.Dir = s.WorkDir

		terminal, err := pty.Start(cmd)
		if err != nil {
			return 1, 400103, err
		}

		go func() {
			for window := range windowCh {
				setWindowSize(terminal, window.Width, window.Height)
			}
		}()

		// var terminalWriters io.Writer
		// if auditor != nil {
		// 	terminalWriters = io.MultiWriter(terminal, auditor)
		// } else {
		// 	terminalWriters = terminal
		// }

		if s.IsNotAllowClientWrite {
			// ctrl + c is allow
			go io.Copy(&ExitSessionWriter{
				CloseHandler: func() {
					session.Close()
					terminal.Close()
				},
			}, session) // stdin
		} else {
			// go io.Copy(terminalWriters, session) // stdin
			go io.Copy(terminal, session) // stdin
		}

		var sessionWriters io.Writer
		if auditor != nil {
			sessionWriters = io.MultiWriter(session, auditor)
		} else {
			sessionWriters = session
		}
		go io.Copy(sessionWriters, terminal) // stdout

		// var writers io.Writer
		// if auditor != nil {
		// 	writers = io.MultiWriter(session, auditor)
		// } else {
		// 	writers = session
		// }
		// go io.Copy(f, session) // stdin
		// go io.Copy(writers, f) // stdout

		cmd.Wait()
		return cmd.ProcessState.ExitCode(), 0, nil
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
			return cmd.ProcessState.ExitCode(), 400104, err
		}

		io.WriteString(session, string(output)+"\n")
		return cmd.ProcessState.ExitCode(), 0, nil
	}

	// 2.2 Disable pseudo-terminal allocation.
	io.WriteString(session, fmt.Sprintf("Hi %s! You've successfully authenticated with %s.\n", session.User(), s.BrandName))
	return 0, 0, nil
}

type TW struct {
	io.Writer
}

func (t *TW) Write(p []byte) (n int, err error) {
	fmt.Println("out:", string(p))
	return len(p), nil
}
