package client

import (
	"bufio"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func IsInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	if fi.Mode()&os.ModeCharDevice != 0 {
		return true
	}

	return false
}

func ReadFromStdin() string {
	text, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.Trim(text, "\n")
}

func ReadPasswordFromStdin() string {
	text, _ := term.ReadPassword(int(syscall.Stdin))
	return strings.Trim(string(text), "\n")
}
