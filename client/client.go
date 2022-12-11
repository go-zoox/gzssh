package client

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

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
	KnowHostsFilePath             string
}

func (c *Client) Connect() error {
	var err error

	var hostkeyCallback ssh.HostKeyCallback
	hostkeyCallback, err = knownhosts.New(c.KnowHostsFilePath)
	if err != nil {
		return fmt.Errorf("failed to read known_hosts: %v", err)
	}

	conf := &ssh.ClientConfig{
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

		conf.Auth = append(conf.Auth, ssh.PublicKeys(signer))
	} else {
		if c.Pass == "" && IsInteractive() {
			fmt.Print("Enter password: ")
			c.Pass = ReadPasswordFromStdin()
		}

		if c.Pass != "" {
			conf.Auth = append(conf.Auth, ssh.Password(c.Pass))
		}
	}

	var conn *ssh.Client

	conn, err = ssh.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port), conf)
	if err != nil {
		return fmt.Errorf("failed to dial ssh: %v", err)
	}
	defer conn.Close()

	var session *ssh.Session
	var stdin io.WriteCloser

	session, err = conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create new session: %v", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

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
