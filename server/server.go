package server

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/go-zoox/datetime"
	"github.com/go-zoox/fs"
	oauthqrcode "github.com/go-zoox/gzssh/utils/oauth-qrcode"
	"github.com/go-zoox/gzssh/utils/qrcode"
	"github.com/go-zoox/ip"
	"github.com/go-zoox/logger"
	lru "github.com/go-zoox/lru"
	gossh "golang.org/x/crypto/ssh"
)

func CreateDefaultOnAuthentication(defaultUser, defaultPass string, isShowUserPass bool) func(remote, version, user, pass string) bool {
	return func(remote, version, user, pass string) bool {
		// logger.Infof("[user: %s][remote: %s] try to connect ...", user, remote)

		isOK := user == defaultUser && pass == defaultPass
		if !isOK {
			if isShowUserPass {
				logger.Infof("[auth: password][user: %s][remote: %s][version: %s] failed to authenticate(user: %s, pass: %s)", user, remote, version, user, pass)
			} else {
				logger.Infof("[auth: password][user: %s][remote: %s][version: %s] failed to authenticate(pass not correct)", user, remote, version)
			}
		} else {
			if isShowUserPass {
				logger.Infof("[auth: password][user: %s][remote: %s][version: %s] succeed to authenticate(user: %s, pass: %s)", user, remote, version, user, pass)
			} else {
				logger.Infof("[auth: password][user: %s][remote: %s][version: %s] succeed to authenticate.", user, remote, version)
			}
		}

		return isOK
	}
}

type Auditor struct {
	io.Writer

	Log func(user, pass string, remote string, isPty bool, isHoneypot bool, log []byte)

	User string

	Pass string

	Remote string

	IsPty bool

	IsHoneypot bool

	// buf []byte
}

func (a *Auditor) Write(p []byte) (n int, err error) {
	n = len(p)

	// fmt.Println(p)

	// for _, b := range p {
	// 	// enter '\r'
	// 	if b == 13 {
	// 		command := strings.TrimSpace(string(a.buf))
	// 		if len(command) != 0 {
	// 			a.Log(a.User, a.Remote, a.IsPty, command)
	// 		}

	// 		a.buf = nil
	// 		continue
	// 	}

	// 	// delete
	// 	if b == 127 {
	// 		bufLength := len(a.buf)
	// 		if a.buf == nil {
	// 			continue
	// 		}

	// 		if bufLength >= 1 {
	// 			a.buf = a.buf[:len(a.buf)-1]
	// 		}
	// 	} else {
	// 		// // ignore
	// 		// if b == 9 {
	// 		// 	// tab
	// 		// 	continue
	// 		// }

	// 		if _, ok := LEGAL_CHARS_MAPPING[b]; ok {
	// 			a.buf = append(a.buf, b)
	// 		}
	// 	}
	// }

	if n != 0 {
		a.Log(a.User, a.Pass, a.Remote, a.IsPty, a.IsHoneypot, p)
	}

	return
}

func CreateDefaultAuditor(auditFn func(user, pass string, remote string, isPty bool, isHoneypot bool, log []byte)) func(user, pass string, remote string, isPty bool, isHoneypot bool) *Auditor {
	return func(user, pass string, remote string, isPty bool, isHoneypot bool) *Auditor {
		return &Auditor{
			Log:        auditFn,
			User:       user,
			Pass:       pass,
			Remote:     remote,
			IsPty:      isPty,
			IsHoneypot: isHoneypot,
		}
	}
}

type Server struct {
	Host        string
	Port        int
	Shell       string
	Environment map[string]string
	// IdleTimeout, unit: seconds
	IdleTimeout int
	// MaxTimeout, unit: seconds
	MaxTimeout int
	//
	OnAuthentication func(remote, version, user, pass string) bool
	OnAudit          func(user, pass string, remote string, isPty bool, isHoneypot bool, log []byte)
	//
	User string
	Pass string
	//
	LogDir string

	StartupCommand        string
	IsNotAllowClientWrite bool

	//
	IsRunInContainer bool
	// cleanup container => 1. destroy container / 2. stop container
	IsContainerAutoCleanupWhenExitDisabled bool
	// destory container based on cleanup
	IsContainerAutoDestroyImmediatelyWhenExit bool
	//
	IsContainerRecoveryDisabled bool
	// IsContainerPrivilegeAllowed means docker container privileged
	IsContainerPrivilegeAllowed bool
	// IsContainerReadonly means docker container readonly rootfs
	IsContainerReadonly bool
	// ContainerReadonlyPaths specifys the readonly paths
	ContainerReadonlyPaths string
	// ContainerNetworkMode options (default | none | container:X)
	ContainerNetworkMode string
	// ContainerNetwork customs the exist external network
	ContainerNetwork string
	// ContainerMaxAge is when container recovery is allowed, recoveried container max age
	//  unit: seconds, default: 3600 (1h)
	ContainerMaxAge int
	WorkDir         string
	PermissionDir   string
	// Container Image
	Image string
	// Container Image Registry User
	ImageRegistryUser string
	// Container Image Registry Pass
	ImageRegistryPass string

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

	// QRCode is qrcode login, should works with auth server
	QRCode bool
	// QRCodeClientID is the oauth server (auth-server) client id
	QRCodeClientID string
	// QRCodeRedirectURI is the oauth server (auth-server) redirect uri
	QRCodeRedirectURI string

	// Version is the GzSSH Version
	Version string

	// Banner is the GzSSH Banner string
	Banner string
	// BannerCallback is the GzSSH callback method for get banner string
	BannerCallback func(conn gossh.ConnMetadata) string

	// ServerEchoVersion is the ssh server echo version, prefix with SSH-2.0-
	//	such as
	//		MacOS 13 => OpenSSH_8.6 (full: SSH-2.0-OpenSSH_8.6)
	//		Ubuntu 22.04 => OpenSSH_8.2p1 Ubuntu-4ubuntu0.4 (full: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4)
	ServerEchoVersion string

	// IsMasqueradeAsOpenSSH will set Server Echo Version as OpenSSH if ServerEchoVersion not set
	IsMasqueradeAsOpenSSH bool

	//
	IsAllowSFTP bool

	//
	IsAllowRemoteForward bool

	//
	IsAllowAudit bool
	AuditLogDir  string

	// IsHoneypot works as a honey pot
	IsHoneypot             bool
	IsHoneypotAllowAllUser bool
	//
	HoneypotUser string
	HoneypotUID  int
	HoneypotGID  int

	// Resource LIMIT
	// Memory is the memory limit for container, such as 100MB = 100M, 1GB=1G
	Memory string
	// CPUs  is the cpu core count limit for container, such as 1, 2
	CPUs float64
	// CPUCount  is the cpu percent limit for container, range: 1~100, such as 10, 80
	CPUPercent int
	//
	CpusetCpus string
	CpusetMems string
	//
	CPUShares int

	//
	auditor func(user, pass string, remote string, isPty bool, isHoneypot bool) *Auditor
}

func (s *Server) Start() error {
	if err := s.defaults(); err != nil {
		return fmt.Errorf("failed to set defaults: %s", err)
	}

	s.Environment["SERVER_BRAND_TYPE_NAME"] = "GZSSH"
	s.Environment["SERVER_BRAND_TYPE_VERSION"] = s.Version
	s.Environment["SERVER_BRAND_NAME"] = s.BrandName
	if s.IsRunInContainer {
		s.Environment["SERVER_RUN_CONTEXT"] = "CONTAINER"
	} else {
		s.Environment["SERVER_RUN_CONTEXT"] = "HOST"
	}

	// if honeypot, force run in container, avoid being attack.
	if s.IsHoneypot {
		s.IsRunInContainer = true
		s.IsContainerAutoDestroyImmediatelyWhenExit = true
		s.IsContainerPrivilegeAllowed = false
		// s.IsContainerAllowRecovery = true
		s.IsAllowAudit = true
		// limit resource avoid server broken
		s.MaxTimeout = 5 * 60
		if s.Memory == "" {
			s.Memory = "48M"
		}
		if s.CPUs == 0 {
			s.CPUs = 1
		}
		if s.CPUPercent == 0 {
			s.CPUPercent = 60
		}
	}

	// if container recovery is enabled, so container will not been destroyed when exit
	if !s.IsContainerRecoveryDisabled {
		s.IsContainerAutoDestroyImmediatelyWhenExit = false
	}

	if s.IsAllowAudit {
		if s.AuditLogDir == "" {
			return fmt.Errorf("audit mode --audit-log-dir is required")
		}

		// if err := os.MkdirAll(s.AuditLogDir, 0766); err != nil {
		// 	return fmt.Errorf("failed to create audit log dir(%s): %s", s.AuditLogDir, err)
		// }

		if s.OnAudit == nil {
			isDirCreatedCache := lru.New(10)

			s.OnAudit = func(user string, pass string, remote string, isPty bool, isHoneypot bool, log []byte) {
				// logger.Infof("[audit][user: %s][remote: %s][pty: %v] writing", user, remote, isPty)
				date := datetime.Now().Format("YYYY-MM-DD")

				if s.AuditLogDir != "" {
					var logFilepath string
					var auditLogDir string
					if !isHoneypot {
						auditLogDir = fmt.Sprintf("%s/%s", s.AuditLogDir, date)
					} else {
						auditLogDir = fmt.Sprintf("%s/%s/honeypot", s.AuditLogDir, date)
					}

					if _, ok := isDirCreatedCache.Get(auditLogDir); !ok {
						if !fs.IsExist(auditLogDir) {
							if err := os.MkdirAll(auditLogDir, 0766); err != nil {
								logger.Infof("failed to create direactory(%s): %s", auditLogDir, fmt.Errorf("failed to create audit log dir(%s): %s", auditLogDir, err))
							}

							isDirCreatedCache.Set(auditLogDir, true)
						}
					}

					if !isHoneypot {
						if isPty {
							logFilepath = fmt.Sprintf("%s/audit_%s_%s_pty.log", auditLogDir, user, remote)
						} else {
							logFilepath = fmt.Sprintf("%s/audit_%s_%s_nopty.log", auditLogDir, user, remote)
						}
					} else {
						if isPty {
							logFilepath = fmt.Sprintf("%s/audit_%s_%s_pty_honeypot_%s.log", auditLogDir, user, remote, pass)
						} else {
							logFilepath = fmt.Sprintf("%s/audit_%s_%s_nopty_honeypot_%s.log", auditLogDir, user, remote, pass)
						}
					}

					f, err := os.OpenFile(logFilepath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0766)
					if err != nil {
						logger.Errorf("failed to open audit log file(%s): %v", logFilepath, err)
						return
					}

					if _, err := f.Write(log); err != nil {
						logger.Warnf("failed to write audit log to %s (err: %v).", s.AuditLogDir, err)
					}
				} else {
					logger.Infof("[audit][user: %s][remote: %s][pty: %v] %s", user, remote, isPty, log)
				}

			}
		}
	}

	if s.OnAudit != nil {
		s.auditor = CreateDefaultAuditor(s.OnAudit)
	}

	ssh.Handle(func(session ssh.Session) {
		var err error
		user := session.User()
		remote := session.RemoteAddr().String()
		exitCode := 0
		code := 0

		if s.QRCode {
			io.WriteString(session, `
########################################
#         SSH Auth via QRCode          #
#          Powered By GZSSH            #
########################################
`)

			// QRCodeClientID: "https://login.zcorky.com"
			// QRCodeClientID: "a83a2f195b847b3d6ecbb4805a6e3509",
			// QRCodeRedirectURI: "https://test-terminal-qrcode.zcork.com/login/doreamon/callback",
			logger.Infof("[handler] create qrcode login instance ...")
			state := oauthqrcode.NewLogin(
				s.AuthServer,
				s.QRCodeClientID,
				s.QRCodeRedirectURI,
			)

			logger.Infof("[handler] wait for getting qrcode url ...")
			qrcodeURL := <-state.GetQRCodeURL()

			logger.Infof("[handler] generate qrcode from qrcode url, then send it to client ...")
			io.Copy(session, qrcode.New(qrcodeURL))

			logger.Infof("[handler] wait client user scan qrcode and checking qrcode status in background ...")
			io.WriteString(session, fmt.Sprintf("[%s] Please scan the qrcode in %d seconds.\n", datetime.Now(), s.IdleTimeout))
			io.WriteString(session, fmt.Sprintf("[%s] 	if you cannot use qrcode, you can also visit the following url in browser: \n%s\n", datetime.Now(), qrcodeURL))

			// time.Sleep(1 * time.Second)
			doneCh := make(chan bool)
			errCh := make(chan error)
			go func() {
				// get status interval
				for {
					if ok, err := state.GetStatus(); err != nil {
						log.Fatalf("failed to get status: %v", err)
					} else if ok {
						// fmt.Println("login success")
						doneCh <- true
						break
					} else {
						// fmt.Printf("waiting for login(status: %s) ...\n", state.GetQRCodeStatus())
						time.Sleep(3 * time.Second)
					}
				}
			}()
			go func() {
				// handle oauth logic
				for {
					select {
					case <-doneCh:
						if err := state.GetToken(); err != nil {
							errCh <- fmt.Errorf("failed to get token: %v", err)
							return
						}

						if err := state.GetUser(); err != nil {
							errCh <- fmt.Errorf("failed to get user: %v", err)
							return
						}

						accessToken, err := state.GetAccessToken()
						if err != nil {
							errCh <- fmt.Errorf("failed to get access token: %v", err)
							return
						}

						if err := oauthqrcode.SetAuthToken(accessToken); err != nil {
							errCh <- fmt.Errorf("failed to set auth token: %v", err)
							return
						}

						// // clear screen
						// clear := exec.Command("clear")
						// clear.Stdout = os.Stdout
						// clear.Run()

						// logger.Info("token: %s", state.GetAccessToken())
						_, err = state.GetAccessToken()
						if err != nil {
							errCh <- fmt.Errorf("failed to get access token: %v", err)
							return
						}

						errCh <- nil
						return
					}
				}
			}()

			// io.WriteString(session, fmt.Sprintf("[%s] QRCode has been scanned by user %s.\n", datetime.Now(), "xxx"))

			// time.Sleep(1 * time.Second)
			// io.WriteString(session, fmt.Sprintf("[%s] QRCode has been confirmed by user %s.\n", datetime.Now(), "xxx"))

			// time.Sleep(1 * time.Second)

			if err := <-errCh; err != nil {
				logger.Infof("[handler] qrcode error(detail: %s).", err)
				io.WriteString(session, fmt.Sprintf("[%s] QRCode failed to authenticate.\n", datetime.Now()))
				session.Exit(1)
				return
			}

			logger.Infof("[handle][user: %s][remote: %s] logined with qrcode user(%s, ssh user: %s) ...", user, remote, state.GetCurrentUser().Nickname, user)
			io.WriteString(session, fmt.Sprintf("[%s] Welcome %s, You have logined SSH(ssh user %s).\n", datetime.Now(), state.GetCurrentUser().Nickname, user))
		}

		logger.Infof("[handle][user: %s][remote: %s] connected ...", user, remote)

		if s.IsRunInContainer {
			exitCode, code, err = s.runInContainer(session)
		} else {
			exitCode, code, err = s.runInHost(session)
		}

		if err != nil {
			logger.Infof("[handle][user: %s][remote: %s] exit(code: %d, code: %d, error: %s).", user, remote, exitCode, code, err)
		} else {
			logger.Infof("[handle][user: %s][remote: %s] exit(code: %d, code: %d).", user, remote, exitCode, code)
		}

		session.Exit(exitCode)
	})

	// if s.ContainerMaxAge == 0 {
	// 	s.ContainerMaxAge = 3600
	// }

	if s.Port == 0 {
		s.Port = 22
	}

	address := fmt.Sprintf("%s:%d", s.Host, s.Port)

	options, err := s.Options()
	if err != nil {
		return fmt.Errorf("failed to get options: %s", err)
	}

	// @TODO echo server info
	options = append(options, func(session *ssh.Server) error {
		internalIP, err := ip.GetInternalIP()
		if err != nil {
			return fmt.Errorf("failed to get internal ip: %v", err)
		}

		publicIP, _ := ip.GetPublicIP()
		// if err != nil {
		// 	return fmt.Errorf("failed to get public ip: %v", err)
		// }

		logger.Infof("[runtime] ip internal: %s", internalIP)
		logger.Infof("[runtime]    public  : %s", publicIP)

		logger.Infof("[runtime] brand: %s", s.BrandName)
		logger.Infof("[runtime] gzssh: %s", s.Version)
		logger.Infof("[runtime] server version: SSH-2.0-%s", s.ServerEchoVersion)
		logger.Infof("[runtime] log dir: %s", s.LogDir)
		if s.Banner != "" {
			logger.Infof("[runtime] banner: %s", s.Banner)
		}
		logger.Infof("")

		if !s.IsRunInContainer {
			logger.Infof("[runtime] mode: %s", "host")
			logger.Infof("")
		} else {
			logger.Infof("[runtime] mode: %s", "container")
			logger.Infof("[runtime] auto cleanup container: %v", !s.IsContainerAutoCleanupWhenExitDisabled)
			logger.Infof("[runtime] auto destroy container: %v", s.IsContainerAutoDestroyImmediatelyWhenExit)

			logger.Infof("[runtime] container recovery: %v", !s.IsContainerRecoveryDisabled)
			if !s.IsContainerAutoDestroyImmediatelyWhenExit {
				logger.Infof("[runtime] container max age: %ds", s.ContainerMaxAge)
			}
			logger.Infof("[runtime] container privileged: %v", s.IsContainerPrivilegeAllowed)
			logger.Infof("[runtime] container readonly: %v", s.IsContainerReadonly)

			if s.ContainerReadonlyPaths != "" {
				logger.Infof("[runtime] container readonly: %s", s.ContainerReadonlyPaths)
			}

			logger.Infof("")
		}
		if s.WorkDir != "" {
			logger.Infof("[runtime] workdir: %s", s.WorkDir)
			logger.Infof("")
		}
		if s.AuthServer != "" {
			if !s.QRCode {
				logger.Infof("")
				logger.Infof("[runtime] auth mode: %s", "auth-server")
				logger.Infof("[runtime] auth server: %s", s.AuthServer)
				logger.Infof("")
			} else {
				logger.Infof("")
				logger.Infof("[runtime] auth mode: %s", "qrcode")
				logger.Infof("[runtime] qrcode auth server: %s", s.AuthServer)
				logger.Infof("[runtime] qrcode client id: %s", s.QRCodeClientID)
				logger.Infof("[runtime] qrcode redirect uri: %s", s.QRCodeRedirectURI)
				logger.Infof("")
			}
		}

		logger.Infof("[runtime] sftp: %v", s.IsAllowSFTP)
		logger.Infof("")
		logger.Infof("[runtime] remote port forward: %v", s.IsAllowRemoteForward)

		logger.Infof("[runtime] audit: %v", s.IsAllowAudit)
		if s.IsAllowAudit {
			if s.AuditLogDir != "" {
				logger.Infof("[runtime] audit mode: %s", "file")
				logger.Infof("[runtime] audit log dir: %s", s.AuditLogDir)
			} else {
				logger.Infof("[runtime] audit mode: %s", "console")
			}
		}

		showResource := false
		if s.Memory != "" {
			if !showResource {
				logger.Infof("")
				showResource = true
			}
			logger.Infof("[runtime] memory: %s", s.Memory)
		}
		if s.CPUs != 0 {
			if !showResource {
				logger.Infof("")
				showResource = true
			}
			logger.Infof("[runtime] cpu cores: %.2f", s.CPUs)
		}
		if s.CPUPercent != 0 {
			if !showResource {
				logger.Infof("")
				showResource = true
			}
			logger.Infof("[runtime] cpu percent: %d", s.CPUPercent)
		}
		if s.IsHoneypot {
			logger.Infof("")
			logger.Infof("[runtime] honeypot: %v", true)
		}

		logger.Infof("")
		logger.Infof("[runtime] starting ssh server at: %s ...", address)
		return nil
	})

	return ssh.ListenAndServe(address, nil, options...)
}

func (s *Server) setSessionUser(sessionID string, authType string, user string, password string, publicKey string) error {
	SessionUserCache.Set(sessionID, &SessionUser{sessionID, authType, user, password, publicKey})
	return nil
}

func (s *Server) getSessionUser(sessionID string) (*SessionUser, error) {
	sessionUser, ok := SessionUserCache.Get(sessionID)
	if !ok {
		return nil, fmt.Errorf("session user not found by session id(%s) (1)", sessionID)
	}

	if v, ok := sessionUser.(*SessionUser); ok {
		return v, nil
	}

	return nil, fmt.Errorf("session user not type of *SessionUser by session id(%s) (2)", sessionID)
}

func (s *Server) getSessionUserPass(session ssh.Session) string {
	sessionUser, err := s.getSessionUser(session.Context().SessionID())
	if err != nil || sessionUser == nil {
		return ""
	}

	return sessionUser.Pass
}
