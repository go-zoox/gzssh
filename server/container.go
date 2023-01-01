package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/dustin/go-humanize"
	"github.com/gliderlabs/ssh"
	"github.com/go-zoox/logger"
)

func (s *Server) runInContainer(session ssh.Session) (int, error) {
	user := session.User()
	remote := session.RemoteAddr().String()
	env := session.Environ()
	ptyReq, _, isPty := session.Pty()

	var auditor *Auditor
	if s.auditor != nil {
		auditor = s.auditor(user, remote, isPty)
	}

	for k, v := range s.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	env = append(env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	env = append(env, fmt.Sprintf("LOGIN_USER=%s", session.User()))

	cfg := &container.Config{
		Image: s.Image,
		// Cmd:          commands,
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

	commands := session.Command()
	if len(commands) != 0 {
		cfg.Cmd = []string{"sh", "-c", strings.Join(commands, " ")}

		if s.auditor != nil {
			for _, c := range commands {
				auditor.Write(append([]byte(c), ' '))
			}

			auditor.Write([]byte{'\r'})
		}
	}

	hostCfg := &container.HostConfig{}
	if s.Memory != "" {
		var memory uint64
		memory, err := humanize.ParseBytes(s.Memory)
		if err != nil {
			return 1, err
		}

		hostCfg.Resources.Memory = int64(memory)
	}
	if s.CPUCount != 0 {
		hostCfg.Resources.CPUCount = int64(s.CPUCount)
	}
	if s.CPUPercent != 0 {
		hostCfg.Resources.CPUCount = int64(s.CPUPercent)
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

	status, cleanup, err := runInDocker(s, cfg, hostCfg, session, auditor)
	defer cleanup()
	if err != nil {
		logger.Errorf("failed to run in docker: %v", err)

		if s.IsHoneypot {
			fmt.Fprintln(session, "server internal error, see server log for detail")
		} else {
			fmt.Fprintln(session, err)
		}
	}

	return int(status), err
}

func runInDocker(s *Server, cfg *container.Config, hostCfg *container.HostConfig, session ssh.Session, auditor *Auditor) (status int64, cleanup func(), err error) {
	containerName := fmt.Sprintf("%s_%s_%d_%s", "gzssh", s.Version, time.Now().UnixMilli(), session.Context().SessionID())
	if s.IsContainerRecoveryAllowed {
		user := session.User()
		remote := session.RemoteAddr().String()

		ip := remote
		parts := strings.Split(remote, ":")
		if len(parts) >= 1 {
			ip = parts[0]
		}

		containerName = fmt.Sprintf("%s_%s_recovery_%s_%s", "gzssh", s.Version, user, ip)
	}

	var docker *client.Client
	docker, err = client.NewClientWithOpts()
	if err != nil {
		return
	}

	status = 0
	cleanup = func() {}

	containerID := ""
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
	if s.IsContainerRecoveryAllowed {
		// var response types.ContainerJSON
		response, errx := docker.ContainerInspect(ctx, containerName)
		if errx != nil {
			logger.Infof("[conatiner] create new container: %s ...", containerName)
			var res container.ContainerCreateCreatedBody
			res, err = docker.ContainerCreate(ctx, cfg, hostCfg, nil, nil, containerName)
			if err != nil {
				status = 1
				return
			}

			containerID = res.ID
		} else {
			containerID = response.ID

			// @TODO if tty change, should update
			if response.Config.Tty != cfg.Tty {
				// docker.ContainerUpdate()

				// cannot update container info => remove old and create new
				logger.Infof("[conatiner][tty change] remove old: %s ...", containerName)
				docker.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{})

				logger.Infof("[conatiner][tty change] create new container: %s ...", containerName)
				var res container.ContainerCreateCreatedBody
				res, err = docker.ContainerCreate(ctx, cfg, hostCfg, nil, nil, containerName)
				if err != nil {
					status = 1
					return
				}

				containerID = res.ID
			} else {
				logger.Infof("[conatiner] recovery old container: %s ...", containerName)
			}

			// err = docker.ContainerStart(ctx, containerID, types.ContainerStartOptions{})
			// if err != nil {
			// 	status = 1
			// 	return
			// }
		}
	} else {
		logger.Infof("[conatiner] create new container: %s ...", containerName)
		var res container.ContainerCreateCreatedBody
		res, err = docker.ContainerCreate(ctx, cfg, hostCfg, nil, nil, containerName)
		if err != nil {
			status = 1
			return
		}

		containerID = res.ID
	}

	cleanup = func() {
		if s.IsContainerAutoRemoveWhenExitDisabled {
			docker.ContainerStop(ctx, containerID, nil)
		} else {
			docker.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{})
		}
	}
	opts := types.ContainerAttachOptions{
		Stdin:  cfg.AttachStdin,
		Stdout: cfg.AttachStdout,
		Stderr: cfg.AttachStderr,
		Stream: true,
	}
	var stream types.HijackedResponse
	stream, err = docker.ContainerAttach(ctx, containerID, opts)
	if err != nil {
		return
	}

	cleanup = func() {
		if s.IsContainerAutoRemoveWhenExitDisabled {
			docker.ContainerStop(ctx, containerID, nil)
		} else {
			docker.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{})
		}

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
			}
		}

		outputErr <- err
	}()

	go func() {
		defer stream.CloseWrite()
		var writers io.Writer
		if auditor != nil {
			writers = io.MultiWriter(stream.Conn, auditor)
		} else {
			writers = stream.Conn
		}

		io.Copy(writers, session)
	}()

	err = docker.ContainerStart(ctx, containerID, types.ContainerStartOptions{})
	if err != nil {
		status = 1
		return
	}

	if cfg.Tty {
		_, winCh, _ := session.Pty()
		go func() {
			for win := range winCh {
				err := docker.ContainerResize(ctx, containerID, types.ResizeOptions{
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

	resultC, errC := docker.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	select {
	case err = <-errC:
		return
	case result := <-resultC:
		status = result.StatusCode
	case err = <-outputErr:
		// wait command result 1 second for status code
		select {
		case <-time.After(1 * time.Second):
			return
		case err = <-errC:
			return
		case result := <-resultC:
			status = result.StatusCode
		}
		return
	}

	return
}
