package sftp

import (
	"io"
	"io/ioutil"

	"github.com/go-zoox/logger"
	"github.com/go-zoox/ssh"
	"github.com/pkg/sftp"
)

// CreateSftp creates a SFTP handler as subsystem
func CreateSftp() func(sess ssh.Session) {
	return func(sess ssh.Session) {
		debugStream := ioutil.Discard
		serverOptions := []sftp.ServerOption{
			sftp.WithDebug(debugStream),
		}
		server, err := sftp.NewServer(
			sess,
			serverOptions...,
		)
		if err != nil {
			logger.Errorf("sftp server init error: %s\n", err)
			return
		}
		if err := server.Serve(); err == io.EOF {
			server.Close()

			logger.Infof("sftp client exited session.")
		} else if err != nil {
			logger.Errorf("sftp server completed with error:", err)
		}
	}
}
