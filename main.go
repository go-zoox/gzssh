package main

import (
	"github.com/go-zoox/cli"
	"github.com/go-zoox/gzssh/commands"
)

func main() {
	app := cli.NewMultipleProgram(&cli.MultipleProgramConfig{
		Name:    "gzssh",
		Usage:   "gzssh is a portable, containered ssh server and client, aliernative to openssh server and client",
		Version: Version,
	})

	commands.RegistryServer(app)
	commands.RegistryClient(app)

	app.Run()
}
