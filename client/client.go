package client

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/go-zoox/gzssh/client/browser"
	"github.com/go-zoox/logger"
	"github.com/go-zoox/zoox"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

type Client struct {
	Host             string
	Port             int
	User             string
	Pass             string
	PrivateKey       string
	PrivateKeySecret string
	//
	IsIgnoreStrictHostKeyChecking bool
	//
	OpenInBrowserAddress string
	//
	IsAudit bool
	//
	KnowHostsFilePath string
	//
	Command string
}

func (c *Client) Connect() error {
	var err error

	var hostkeyCallback ssh.HostKeyCallback
	hostkeyCallback, err = knownhosts.New(c.KnowHostsFilePath)
	if err != nil {
		return fmt.Errorf("failed to read known_hosts: %v", err)
	}

	sshConf := &ssh.ClientConfig{
		User: c.User,
		// Auth:            []ssh.AuthMethod{},
		// HostKeyCallback: hostkeyCallback,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if c.IsIgnoreStrictHostKeyChecking {
				return nil
			}

			return hostkeyCallback(hostname, remote, key)
		},
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoRSA,
			ssh.KeyAlgoDSA,
			ssh.KeyAlgoRSASHA512,
			ssh.KeyAlgoRSASHA256,
			ssh.CertAlgoRSASHA512v01,
			ssh.CertAlgoRSASHA256v01,
			ssh.CertAlgoRSAv01,
			ssh.CertAlgoDSAv01,
			ssh.CertAlgoECDSA256v01,
			ssh.CertAlgoECDSA384v01,
			ssh.CertAlgoECDSA521v01,
			ssh.CertAlgoED25519v01,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA521,
		},
	}

	if c.PrivateKey != "" {
		var signer ssh.Signer
		if c.PrivateKeySecret == "" {
			signer, err = ssh.ParsePrivateKey([]byte(c.PrivateKey))
			if err != nil {
				if err.Error() != (&ssh.PassphraseMissingError{}).Error() {
					return fmt.Errorf("failed to parse private key: %v", err)
				}
				// can interactive
				if ok := IsInteractive(); !ok {
					return err
				}

				fmt.Print("Enter passphrase for key: ")
				c.PrivateKeySecret = ReadPasswordFromStdin()

				signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(c.PrivateKey), []byte(c.PrivateKeySecret))
				if err != nil {
					return fmt.Errorf("failed to parse private key (protected): %v", err)
				}
			}
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(c.PrivateKey), []byte(c.PrivateKeySecret))
			if err != nil {
				return fmt.Errorf("failed to parse private key (protected): %v", err)
			}
		}

		sshConf.Auth = append(sshConf.Auth, ssh.PublicKeys(signer))
	} else {
		if c.Pass == "" && IsInteractive() {
			fmt.Printf("Enter password for %s@%s:%d: ", c.User, c.Host, c.Port)
			c.Pass = ReadPasswordFromStdin()
			fmt.Println("")
		}

		if c.Pass != "" {
			sshConf.Auth = append(sshConf.Auth, ssh.Password(c.Pass))
		}
	}

	// WebSSH: https://gitee.com/wida/webssh
	if c.OpenInBrowserAddress != "" {
		return c.ServeAndOpenBrowser(sshConf)
	}

	var sshClient *ssh.Client

	sshClient, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port), sshConf)
	if err != nil {
		return fmt.Errorf("failed to dial ssh: %v", err)
	}
	defer sshClient.Close()

	var session *ssh.Session
	var stdin io.WriteCloser

	session, err = sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create new session: %v", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if c.Command != "" {
		return session.Run(c.Command)
	}

	stdin, err = session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %v", err)
	}

	// configure terminal mode
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// get terminal size
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return fmt.Errorf("failed to get terminal width and height")
	}

	// run terminal session
	if err = session.RequestPty("xterm", height, width, modes); err != nil {
		return fmt.Errorf("failed to request pty: %v", err)
	}

	// start remote shell
	if err = session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %v", err)
	}

	//
	// signal.Ignore(syscall.SIGINT)

	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		for {
			s := <-sigc
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				// if err := session.Signal(ssh.SIGINT); err != nil {
				// 	logger.Errorf("failed to send signal SIGINT: %v", err)
				// }

				// issue: https://github.com/golang/go/issues/16597#issuecomment-548053530
				// question: Looks like ssh.SIGINT is not supported by OpenSSH
				// solution: https://github.com/mihaitodor/wormhole/blob/d5fbc432650a7ccdc9d8b80890dd58c19e236279/transport/transport.go#L107

				stdin.Write([]byte("\x03"))
			}
		}
	}()

	// Accepting commands
	// inspired by: https://github.com/inatus/ssh-client-go
	for {
		reader := bufio.NewReader(os.Stdin)
		str, err := reader.ReadString('\n')
		if err == io.EOF {
			return nil
		}

		fmt.Fprint(stdin, str)
	}
}

// func (c *Client) runTerminal(sshClient *ssh.Client, shell string, stdout, stderr io.Writer, stdin io.Reader, w, h int, wsConn *zoox.WebSocketConn) error {
// 	if sshClient == nil {
// 		return fmt.Errorf("ssh client is not ready")
// 	}

// 	sshSession, err := sshClient.NewSession()
// 	if err != nil {
// 		logger.Error(err.Error())
// 		return err
// 	}

// 	defer func() {
// 		_ = sshSession.Close()
// 	}()

// 	sshSession.Stdout = stdout
// 	sshSession.Stderr = stderr
// 	sshSession.Stdin = stdin

// 	modes := ssh.TerminalModes{}

// 	if err := sshSession.RequestPty("xterm-256color", h, w, modes); err != nil {
// 		return err
// 	}

// 	err = sshSession.Run(shell)
// 	if err != nil {
// 		logger.Errorf("ssh session run shell error: %v", err)
// 		return err
// 	}

// 	return nil
// }

func (c *Client) ServeAndOpenBrowser(sshConf *ssh.ClientConfig) error {
	logger.Infof("Please visit browser: http://%s", c.OpenInBrowserAddress)

	return browser.Serve(c.OpenInBrowserAddress, func(zc *zoox.Context, wsConn *websocket.Conn) {
		sshClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port), sshConf)
		if err != nil {
			logger.Errorf("failed to dial ssh: %v", err)
			return
		}
		defer sshClient.Close()

		// go io.Copy(session, client.WebSocketConn)

		// wsStdin := &WsStin{
		// 	Stream: make(chan []byte),
		// 	Err:    make(chan error),
		// }

		// session.Stdin = wsStdin
		// session.Stdout = &WsStdout{Client: client}
		// session.Stderr = &WsStdout{Client: client}

		// client.OnTextMessage = func(msg []byte) {
		// 	if _, err := session.Stdout.Write(msg); err != nil {
		// 		ctx.Logger.Warn("failed to write to session")
		// 	}

		// 	wsStdin.Stream <- msg
		// }

		// // go io.Copy(session.StdinPipe(), client.WebSocketConn)
		// isTerminalCreated := false

		// client.OnTextMessage = func(msg []byte) {
		// 	if !isTerminalCreated {
		// 		isTerminalCreated = true

		// 		c.runTerminal(
		// 			sshClient,
		// 			"sh",
		// 			client.WebSocketConn,
		// 			client.WebSocketConn,
		// 			client.WebSocketConn,
		// 			cols*10,
		// 			rows*10,
		// 		)
		// 		return
		// 	}
		// 	fmt.Println("receive message:", string(msg))
		// }

		var recorder *Recorder
		if c.IsAudit {
			recorder = NewRecorder(os.Stdout)
		}

		turn, err := NewTurn(wsConn, sshClient, recorder)
		if err != nil {
			wsConn.Close()
			return
		}
		defer turn.Close()
		go func() {
			closed := false
			wsConn.SetCloseHandler(func(code int, text string) error {
				if closed {
					return nil
				}

				closed = true
				return turn.Close()
			})
		}()

		var logBuff = bufPool.Get().(*bytes.Buffer)
		logBuff.Reset()
		defer bufPool.Put(logBuff)

		ctx, cancel := context.WithCancel(context.Background())
		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			defer wg.Done()
			err := turn.LoopRead(logBuff, ctx)
			if err != nil {
				logger.Infof("loop read error: %#v", err)
			}
		}()
		go func() {
			defer wg.Done()
			err := turn.SessionWait()
			if err != nil {
				logger.Infof("session wait error: %#v", err)
			}
			cancel()
		}()
		wg.Wait()
	})
}

// type WsStdout struct {
// 	io.Writer

// 	Client *zoox.WebSocketClient
// }

// func (w *WsStdout) Write(p []byte) (n int, err error) {
// 	if err = w.Client.WriteText(p); err != nil {
// 		return 0, err
// 	}

// 	return len(p), nil
// }

// type WsStin struct {
// 	io.Reader

// 	Stream chan []byte
// 	Err    chan error
// }

// func (w *WsStin) Read(p []byte) (n int, err error) {
// 	n = copy(p, <-w.Stream)
// 	return n, nil
// }
