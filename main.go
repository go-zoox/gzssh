package main

import (
	"github.com/go-zoox/cli"
	"github.com/go-zoox/gzssh/commands"
)

func main() {
	app := cli.NewMultipleProgram(&cli.MultipleProgramConfig{
		Name:  "multiple",
		Usage: "multiple is a program that has multiple commands.",
	})

	commands.RegistryServer(app)
	commands.RegistryClient(app)

	app.Run()
}
