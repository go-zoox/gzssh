package user

import (
	"encoding/json"
	"fmt"

	"github.com/go-zoox/fetch"
	"github.com/go-zoox/gzssh/utils/oauth-qrcode/request"
)

const path = "/api/v1/user"

type User interface {
	Get() (*UserImpl, error)
}

type UserImpl struct {
	ID       int64  `json:"id"`
	Nickname string `json:"nickname"`
	Avatar   string `json:"avatar"`
	Email    string `json:"email"`
	OpenID   string `json:"open_id"`
}

type user struct {
	client request.Request
}

func New(client request.Request) User {
	return &user{client}
}

func (c *user) Get() (*UserImpl, error) {
	response, err := c.client.Get(path, &fetch.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %v", err)
	}

	userRaw := response.Get("result").String()
	if userRaw == "" {
		return nil, fmt.Errorf("cannot get user: %v", response.String())
	}

	var u UserImpl
	if err := json.Unmarshal([]byte(userRaw), &u); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %v", err)
	}

	return &u, nil
}
