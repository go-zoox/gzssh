package config

import (
	"fmt"

	"github.com/go-zoox/fetch"
	"github.com/go-zoox/gzssh/utils/oauth-qrcode/request"
)

// const path = "/config/:uuid"
const path = "/api/v1/client/configs/:uuid"

type Config interface {
	Get(uuid string) (string, error)
}

type config struct {
	client request.Request
}

func New(client request.Request) Config {
	return &config{client}
}

func (c *config) Get(uuid string) (string, error) {
	response, err := c.client.Get(path, &fetch.Config{
		Params: map[string]string{
			"uuid": uuid,
		},
		// Timeout: 30,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get config: %v", err)
		// return "", errors.New("服务器开小差，无法获取配置")
	}

	return response.Get("result.config").String(), nil
}
