package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/dustin/go-humanize"
	"github.com/gliderlabs/ssh"
	"github.com/go-zoox/datetime"
	"github.com/go-zoox/logger"
)

func (s *Server) runInContainer(session ssh.Session) (int, int, error) {
	if s.Shell == "" {
		s.Shell = "sh"
	}

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

	commands := []string{}
	if s.StartupCommand != "" {
		commands = append(commands, s.StartupCommand)
		if !s.IsNotAllowClientWrite {
			commands = append(commands, s.Shell)
		}
	}

	sessionCommands := session.Command()
	if len(sessionCommands) != 0 {
		commands = append(commands, strings.Join(sessionCommands, " "))
	}

	if len(commands) != 0 {
		mergedCommand := strings.Join(commands, " && ")
		cfg.Cmd = []string{"sh", "-c", mergedCommand}

		// auditor.Write([]byte(mergedCommand + "\r"))

		logger.Infof("[container] entrypoint command:", cfg.Cmd)
	}

	hostCfg := &container.HostConfig{}
	if s.Memory != "" {
		var memory uint64
		memory, err := humanize.ParseBytes(s.Memory)
		if err != nil {
			return 1, 400015, err
		}

		hostCfg.Resources.Memory = int64(memory)
	}

	if s.CPUPercent > 0 {
		// hostCfg.Resources.CPUPercent = int64(s.CPUPercent)

		// issue: failed to run in docker: Error response from daemon: Conflicting options: Nano CPUs and CPU Period cannot both be set
		// github: https://github.com/docker/docker-py/issues/1920#issuecomment-505406784
		hostCfg.Resources.NanoCPUs = 0

		// https://www.elephdev.com/cDocker/296.html?ref=addtabs&lang=zh-cn
		// cpu-period：指刷新时间,单位是微秒（us），默认值是0.1秒，即100,000us
		// cpu-quota：容器占用时间,单位是微秒（us）,默认是-1，即不限制
		if hostCfg.Resources.CPUPeriod == 0 {
			hostCfg.Resources.CPUPeriod = 100000
		}

		// https://stackoverflow.com/questions/68999736/whether-the-cpus-means-logical-cpu-processors
		// Linux kernel's CFS bandwidth control mechanism: https://www.kernel.org/doc/html/latest/scheduler/sched-bwc.html
		hostCfg.Resources.CPUQuota = hostCfg.Resources.CPUPeriod * int64(s.CPUPercent) / 100
	}

	// https://unihon.github.io/2019-08/specify-memory-and-cpu-of-the-container/
	if s.CPUs > 0 {
		// hostCfg.Resources.CPUCount = int64(s.CPUCount)

		// CPUQuota = CPUQuota * CPUs / SystemCPUCores
		if hostCfg.Resources.CPUQuota != 0 {
			hostCfg.Resources.CPUQuota = hostCfg.Resources.CPUQuota * int64(s.CPUs*100) / 100 / int64(runtime.NumCPU())
		} else {
			// –cpus 容器CPU占用主机的CPU的比例
			// –cpus=2比–cpus=1，占用比例要大。
			// 在 docker inspect 3ef363848eb8 | grep Cpu 中有个 NanoCpus 会随其规律性变化。
			hostCfg.Resources.NanoCPUs = int64(s.CPUs * 1e9)
		}
	}

	// –cpuset-cpus：指定允许容器使用的CPU序号,从0开始，默认使用主机的所有CPU
	if s.CpusetCpus != "" {
		hostCfg.Resources.CpusetCpus = s.CpusetCpus
	}
	if s.CpusetMems != "" {
		hostCfg.Resources.CpusetMems = s.CpusetMems
	}
	// –cpu-shares 是相对权重， 设置为一个正整数，代表所分配的相对CPU资源比，需要注意的是，这种情况只发生在CPU资源紧张的情况下
	if s.CPUShares > 0 {
		hostCfg.Resources.CPUShares = int64(s.CPUShares)
	}

	hostCfg.Privileged = s.IsContainerPrivilegeAllowed
	hostCfg.ReadonlyRootfs = s.IsContainerReadonly
	if s.ContainerReadonlyPaths != "" {
		if hostCfg.ReadonlyPaths == nil {
			hostCfg.ReadonlyPaths = []string{}
		}
		paths := strings.Split(s.ContainerReadonlyPaths, ",")
		if len(paths) > 0 {
			hostCfg.ReadonlyPaths = append(hostCfg.ReadonlyPaths, paths...)
		}
	}
	if s.ContainerNetworkMode != "" {
		hostCfg.NetworkMode = container.NetworkMode(s.ContainerNetworkMode)
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

	containerName := s.getContainerName(session)

	var networkCfg *network.NetworkingConfig
	if s.ContainerNetwork != "" {
		networkCfg = &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{},
		}
		networkCfg.EndpointsConfig[s.ContainerNetwork] = &network.EndpointSettings{
			NetworkID: s.ContainerNetwork,
			// Aliases: []string{
			// 	containerName,
			// },
		}
	}

	status, code, cleanup, err := runInDocker(s, cfg, hostCfg, networkCfg, session, auditor, containerName)
	if !s.IsContainerAutoCleanupWhenExitDisabled {
		defer cleanup()
	}

	if err != nil {
		logger.Errorf("failed to run in docker: %v", err)

		if s.IsHoneypot {
			fmt.Fprintln(session, "server internal error, see server log for detail")
		} else {
			fmt.Fprintln(session, err)
		}
	}

	return int(status), int(code), err
}

func (s *Server) getContainerName(session ssh.Session) string {
	user := session.User()
	remote := session.RemoteAddr().String()
	ip := remote
	parts := strings.Split(remote, ":")
	if len(parts) >= 1 {
		ip = parts[0]
	}

	containerName := fmt.Sprintf("%s_%s_dynamic_%s_%s_%d_%s", "gzssh", s.Version, user, ip, time.Now().UnixMilli(), session.Context().SessionID())
	if s.IsContainerRecoveryAllowed {
		containerName = fmt.Sprintf("%s_%s_recovery_%s_%s", "gzssh", s.Version, user, ip)
	}

	return containerName
}

func runInDocker(s *Server, cfg *container.Config, hostCfg *container.HostConfig, networkCfg *network.NetworkingConfig, session ssh.Session, auditor *Auditor, containerName string) (status int64, code int64, cleanup func(), err error) {
	var docker *client.Client
	docker, err = client.NewClientWithOpts()
	if err != nil {
		return
	}

	status = 0
	code = 0
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
				status = 1
				code = 400001
				return
			}
			imagePullCfg.RegistryAuth = base64.URLEncoding.EncodeToString(encodedJSON)
		}
		pullResponse, err = docker.ImagePull(ctx, cfg.Image, imagePullCfg)
		if err != nil {
			status = 1
			code = 400002
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
			res, err = docker.ContainerCreate(ctx, cfg, hostCfg, networkCfg, nil, containerName)
			if err != nil {
				status = 1
				code = 400003
				return
			}

			containerID = res.ID
		} else {
			containerID = response.ID

			// @TODO if tty change, should update
			if response.Config.Tty != cfg.Tty {
				// docker.ContainerUpdate()

				if response.State.Running {
					logger.Infof("[conatiner][tty change]] stop running: %s ...", containerName)
					err = docker.ContainerStop(ctx, containerID, nil)
					if err != nil {
						status = 1
						code = 400004
						return
					}
				}

				// cannot update container info => remove old and create new
				logger.Infof("[conatiner][tty change] remove old: %s ...", containerName)
				docker.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{})

				logger.Infof("[conatiner][tty change] create new container: %s ...", containerName)
				var res container.ContainerCreateCreatedBody
				res, err = docker.ContainerCreate(ctx, cfg, hostCfg, networkCfg, nil, containerName)
				if err != nil {
					status = 1
					code = 400005
					return
				}

				containerID = res.ID
			} else {
				var containerCreatedAt *datetime.DateTime
				// response.Created: 2023-01-01T07:07:01.034325879Z
				// containerCreatedAt, err = datetime.FromPattern("2006-01-02T15:04:05.000Z", response.Created)
				// https://stackoverflow.com/questions/25845172/parsing-rfc-3339-iso-8601-date-time-string-in-go
				var responseCreatedAt time.Time
				now := datetime.FromTime(time.Now())

				// layout := "2006-01-02T15:04:05.000000000Z"
				layout := time.RFC3339
				responseCreatedAt, err = time.Parse(layout, response.Created)
				time.LoadLocation("")

				if err != nil {
					status = 1
					code = 400006
					return
				}
				containerCreatedAt = datetime.FromTime(responseCreatedAt.In(now.Location()))

				isContainerExpired := !containerCreatedAt.Add(time.Duration(s.ContainerMaxAge) * time.Second).After(now)
				if isContainerExpired {
					logger.Infof("maxAge:", s.ContainerMaxAge)
					logger.Infof("create:", containerCreatedAt.Format("YYYY-MM-DD HH:mm:ss"))
					logger.Infof("create + maxAge:", containerCreatedAt.Add(time.Duration(s.ContainerMaxAge)*time.Second).Format("YYYY-MM-DD HH:mm:ss"))
					logger.Infof("now:", now, now.Location())

					if response.State.Running {
						logger.Infof("[conatiner][alive: expired] stop running: %s ...", containerName)
						err = docker.ContainerStop(ctx, containerID, nil)
						if err != nil {
							status = 1
							code = 400007
							return
						}
					}

					logger.Infof("[conatiner][alive: expired] remove old: %s ...", containerName)
					err = docker.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{})
					if err != nil {
						status = 1
						code = 400008
						return
					}

					logger.Infof("[conatiner][alive: expired] create new container: %s ...", containerName)
					var res container.ContainerCreateCreatedBody
					res, err = docker.ContainerCreate(ctx, cfg, hostCfg, networkCfg, nil, containerName)
					if err != nil {
						status = 1
						code = 400009
						return
					}

					containerID = res.ID
				} else {
					logger.Infof("[conatiner] recovery old container: %s ...", containerName)
				}
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
		res, err = docker.ContainerCreate(ctx, cfg, hostCfg, networkCfg, nil, containerName)
		if err != nil {
			status = 1
			code = 400010
			return
		}

		containerID = res.ID
	}

	cleanup = func() {
		if s.IsContainerAutoRemoveWhenExitDisabled {
			logger.Infof("[container] cleanup => stop ...")
			docker.ContainerStop(ctx, containerID, nil)
		} else {
			logger.Infof("[container] cleanup => destory ...")
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
		status = 1
		code = 400011
		return
	}

	cleanup = func() {
		if s.IsContainerAutoRemoveWhenExitDisabled {
			logger.Infof("[container] cleanup => stop ...")
			docker.ContainerStop(ctx, containerID, nil)
		} else {
			logger.Infof("[container] cleanup => destory ...")
			docker.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{})
		}

		stream.Close()
	}

	outputErr := make(chan error)

	go func() {
		var err error
		// _, err = io.Copy(session, stream.Reader)
		var sessionOutput io.Writer
		if auditor != nil {
			sessionOutput = io.MultiWriter(session, auditor)
		} else {
			sessionOutput = session
		}

		if cfg.Tty {
			io.Copy(sessionOutput, stream.Reader) // stdout
		} else {
			if len(session.Command()) != 0 {
				_, err = stdcopy.StdCopy(sessionOutput, session.Stderr(), stream.Reader)
			} else {
				_, err = io.WriteString(sessionOutput, fmt.Sprintf("Hi %s! You've successfully authenticated with %s (Containered).\n", session.User(), s.BrandName))
			}
		}

		outputErr <- err
	}()

	go func() {
		if s.IsNotAllowClientWrite {
			// ctrl + c is allow
			io.Copy(&ExitSessionWriter{
				CloseHandler: func() {
					session.Close()
					stream.CloseWrite()
				},
			}, session) // stdin
			return
		}

		defer stream.CloseWrite()

		// var terminalWriters io.Writer
		// if auditor != nil {
		// 	terminalWriters = io.MultiWriter(stream.Conn, auditor)
		// } else {
		// 	terminalWriters = stream.Conn
		// }
		// io.Copy(terminalWriters, session) // stdin

		io.Copy(stream.Conn, session)
	}()

	err = docker.ContainerStart(ctx, containerID, types.ContainerStartOptions{})
	if err != nil {
		status = 1
		code = 400012
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
					status = 1
					code = 400013
					log.Println(err)
					break
				}
			}
		}()
	}

	resultC, errC := docker.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	select {
	case err = <-errC:
		status = 1
		code = 400014
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
			return
		}
	}

	return
}
