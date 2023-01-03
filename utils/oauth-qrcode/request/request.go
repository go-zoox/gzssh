package request

import (
	"github.com/go-zoox/fetch"
)

type Request interface {
	Get(service string, cfg *fetch.Config) (*fetch.Response, error)
}

type request struct {
	// example: https://zzz.com
	Server string
	//
	ClientID     string
	ClientSecret string
	Token        string
}

func New(server, clientID, clientSecret, token string) Request {
	return &request{
		Server:       server,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Token:        token,
	}
}

func (r *request) Get(service string, cfg *fetch.Config) (*fetch.Response, error) {
	if cfg.Headers == nil {
		cfg.Headers = fetch.Headers{}
	}

	cfg.BaseURL = r.Server
	if r.ClientID != "" && r.ClientSecret != "" {
		cfg.Headers.Set("X-Client-ID", r.ClientID)
		cfg.Headers.Set("X-Client-Secret", r.ClientSecret)
	}

	if r.Token != "" {
		cfg.Headers.Set("Authorization", "Bearer "+r.Token)
	}

	return fetch.Get(service, cfg)
}
