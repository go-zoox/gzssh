package oauthqrcode

import (
	"fmt"
	"os"

	"github.com/go-zoox/fs"
	"github.com/go-zoox/fs/type/yaml"

	"github.com/go-zoox/config"
)

var configName = ".eunomia.yml"

type Config struct {
	Token string `config:"auth_token" yaml:"auth_token"`
}

func LoadConfig() (*Config, error) {
	homeDir, _ := os.UserHomeDir()
	configFile := fs.JoinPath(homeDir, configName)

	if !fs.IsExist(configFile) {
		if err := fs.CreateFile(configFile); err != nil {
			return nil, fmt.Errorf("failed to init config: %s", err)
		}
	}

	var cfg Config
	if err := config.Load(&cfg, &config.LoadOptions{
		FilePath: configFile,
	}); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func SetAuthToken(token string) error {
	homeDir, _ := os.UserHomeDir()
	configFile := fs.JoinPath(homeDir, configName)

	cfg, err := LoadConfig()
	if err != nil {
		cfg = &Config{}
	}

	cfg.Token = token

	return yaml.Write(configFile, cfg)
}
