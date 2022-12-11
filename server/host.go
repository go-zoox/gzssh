package server

import (
	"fmt"
	"io"
	"os/exec"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
)

func (s *Server) runInHost(session ssh.Session) {
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
}
