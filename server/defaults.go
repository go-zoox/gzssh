package server

import (
	"fmt"

	"github.com/go-zoox/fs"
	"github.com/go-zoox/logger"
	"github.com/go-zoox/logger/components/transport"
	"github.com/go-zoox/logger/transport/file"
	"golang.org/x/crypto/ssh"
)

func (s *Server) defaults() error {
	if s.BrandName == "" {
		s.BrandName = "GZSSH"
	}

	if s.IdleTimeout == 0 {
		s.IdleTimeout = 60
	}

	if s.IsNotAllowClientWrite && s.StartupCommand == "" {
		return fmt.Errorf("startup command not set, --no-write should work with --startup-command")
	}

	if s.Environment == nil {
		s.Environment = map[string]string{}
	}

	if s.OnAuthentication == nil {
		s.OnAuthentication = CreateDefaultOnAuthentication(s.User, s.Pass, s.IsHoneypot)
	}

	if s.QRCode && s.AuthServer == "" {
		s.AuthServer = "https://login.zcorky.com"
	}

	if s.Banner != "" {
		s.BannerCallback = func(conn ssh.ConnMetadata) string {
			return s.Banner
		}
	}

	if s.LogDir != "" {
		if !fs.IsExist(s.LogDir) {
			if err := fs.Mkdirp(s.LogDir); err != nil {
				return fmt.Errorf("failed to create dir(%s): %v", s.LogDir, err)
			}
		}

		if stat, err := fs.Stat(s.LogDir); err != nil {
			if stat.Mode().Perm()&(1<<(uint(7))) == 0 {
				return fmt.Errorf("user has no permission when create dir(%s): %v", s.LogDir, err)
			}
		}

		logger.AppendTransports(map[string]transport.Transport{
			"access": file.New(&file.Config{
				Level: "debug",
				File:  fs.JoinPath(s.LogDir, "access.log"),
			}),
		})

		// set audit log dir based on log dir
		s.AuditLogDir = fmt.Sprintf("%s/audit", s.LogDir)
	}

	return nil
}
