package server

import (
	"fmt"

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

	return nil
}
