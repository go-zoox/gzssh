package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/gliderlabs/ssh"
	"github.com/go-zoox/logger"
)

func (s *Server) runInContainer(session ssh.Session) (exitCode int) {
	env := session.Environ()
	ptyReq, _, isPty := session.Pty()

	for k, v := range s.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	env = append(env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	env = append(env, fmt.Sprintf("LOGIN_USER=%s", session.User()))

	cfg := &container.Config{
		Image:        s.Image,
		Cmd:          session.Command(),
		Env:          env,
		Tty:          isPty,
		OpenStdin:    true,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		StdinOnce:    true,
		Volumes:      make(map[string]struct{}),
		Hostname:     s.BrandName,
		WorkingDir:   s.WorkDir,
		// User:         session.User(),
		// User: "1000:1000",
	}

	if s.IsHoneypot {
		// user := session.User()
		// cfg.Env = append(cfg.Env, fmt.Sprintf("HOME=/home/%s", user))
		// cfg.Env = append(cfg.Env, fmt.Sprintf("USER=%s", user))
		// cfg.WorkingDir = fmt.Sprintf("/home/%s", user)

		if s.HoneypotUser != "" {
			cfg.User = s.HoneypotUser
		}

		if s.HoneypotUID != 0 {
			if s.HoneypotGID != 0 {
				cfg.User = fmt.Sprintf("%d:%d", s.HoneypotUID, s.HoneypotGID)
			} else {
				cfg.User = fmt.Sprintf("%d", s.HoneypotUID)
			}
		}
	}

	status, cleanup, err := runInDocker(s, cfg, session)
	defer cleanup()
	if err != nil {
		fmt.Fprintln(session, err)
		logger.Errorf("failed to run in docker: %v", err)
	}

	exitCode = int(status)
	return
}

func runInDocker(s *Server, cfg *container.Config, session ssh.Session) (status int64, cleanup func(), err error) {
	var docker *client.Client
	docker, err = client.NewClientWithOpts()
	if err != nil {
		return
	}

	status = 255
	cleanup = func() {}

	var res container.ContainerCreateCreatedBody
	ctx := context.Background()

	if _, _, err = docker.ImageInspectWithRaw(ctx, cfg.Image); err != nil {
		logger.Infof("[container][image] pulling %s ...", cfg.Image)

		var pullResponse io.ReadCloser
		imagePullCfg := types.ImagePullOptions{}
		if s.ImageRegistryUser != "" || s.ImageRegistryPass != "" {
			authConfig := types.AuthConfig{
				Username: s.ImageRegistryUser,
				Password: s.ImageRegistryPass,
			}
			var encodedJSON []byte
			encodedJSON, err = json.Marshal(authConfig)
			if err != nil {
				return
			}
			imagePullCfg.RegistryAuth = base64.URLEncoding.EncodeToString(encodedJSON)
		}
		pullResponse, err = docker.ImagePull(ctx, cfg.Image, imagePullCfg)
		if err != nil {
			return
		}
		io.Copy(os.Stdout, pullResponse)
		// defer pullResponse.Close()

		logger.Infof("[container][image] pull %s done.", cfg.Image)
	}

	logger.Infof("[conatiner] run with image: %s ...", cfg.Image)
	res, err = docker.ContainerCreate(ctx, cfg, nil, nil, nil, "")
	if err != nil {
		return
	}

	cleanup = func() {
		docker.ContainerRemove(ctx, res.ID, types.ContainerRemoveOptions{})
	}
	opts := types.ContainerAttachOptions{
		Stdin:  cfg.AttachStdin,
		Stdout: cfg.AttachStdout,
		Stderr: cfg.AttachStderr,
		Stream: true,
	}
	var stream types.HijackedResponse
	stream, err = docker.ContainerAttach(ctx, res.ID, opts)
	if err != nil {
		return
	}

	cleanup = func() {
		docker.ContainerRemove(ctx, res.ID, types.ContainerRemoveOptions{})
		stream.Close()
	}

	outputErr := make(chan error)

	go func() {
		var err error
		if cfg.Tty {
			_, err = io.Copy(session, stream.Reader)
		} else {
			if len(session.Command()) != 0 {
				_, err = stdcopy.StdCopy(session, session.Stderr(), stream.Reader)
			} else {
				_, err = io.WriteString(session, fmt.Sprintf("Hi %s! You've successfully authenticated with %s (Containered).\n", session.User(), s.BrandName))
				status = 0
			}
		}

		outputErr <- err
	}()

	go func() {
		defer stream.CloseWrite()
		var writers io.Writer
		if s.auditor != nil {
			writers = io.MultiWriter(stream.Conn, s.auditor(session.User()))
		} else {
			writers = stream.Conn
		}

		io.Copy(writers, session)
	}()

	err = docker.ContainerStart(ctx, res.ID, types.ContainerStartOptions{})
	if err != nil {
		return
	}

	if cfg.Tty {
		_, winCh, _ := session.Pty()
		go func() {
			for win := range winCh {
				err := docker.ContainerResize(ctx, res.ID, types.ResizeOptions{
					Height: uint(win.Height),
					Width:  uint(win.Width),
				})
				if err != nil {
					log.Println(err)
					break
				}
			}
		}()
	}

	resultC, errC := docker.ContainerWait(ctx, res.ID, container.WaitConditionNotRunning)
	select {
	case err = <-errC:
		return
	case result := <-resultC:
		status = result.StatusCode
	case err = <-outputErr:
		return
	}

	return
}
