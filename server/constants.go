package server

import "github.com/go-zoox/lru"

var LEGAL_CHARS_MAPPING = map[byte]bool{}

var LEGAL_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+`~<>,.;':\"[]{}\\| \t\v"

func init() {
	for _, char := range LEGAL_CHARS {
		LEGAL_CHARS_MAPPING[byte(char)] = true
	}
}

var SessionUserCache = lru.New(1000)

type SessionUser struct {
	SessionID string
	AuthType  string // password | publickey
	User      string
	Pass      string
	PublicKey string
}
