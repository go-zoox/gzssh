package oauthqrcode

import (
	"github.com/go-zoox/gzssh/utils/oauth-qrcode/config"
	"github.com/go-zoox/gzssh/utils/oauth-qrcode/request"
	"github.com/go-zoox/gzssh/utils/oauth-qrcode/user"
)

type Client interface {
	// Request() request.Request
	Config() config.Config
	User() user.User
}

type ClientConfig struct {
	Server string
	//
	ClientID     string
	ClientSecret string
	Token        string
}

type client struct {
	request request.Request
}

func New(cfg *ClientConfig) Client {
	return &client{
		request: request.New(cfg.Server, cfg.ClientID, cfg.ClientSecret, cfg.Token),
	}
}

func (c *client) Config() config.Config {
	return config.New(c.request)
}

func (c *client) User() user.User {
	return user.New(c.request)
}
