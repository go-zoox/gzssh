package server

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

func setWindowSize(f *os.File, w, h int) {
	syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})),
	)
}

type ExitSessionWriter struct {
	io.Writer

	CloseHandler func()
}

func (e *ExitSessionWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	if n == 0 {
		return
	}

	if n == 1 {
		// Ctrl + C
		if p[0] == 3 {
			e.CloseHandler()
			return
		}

		// Ctrl + D
		if p[0] == 4 {
			e.CloseHandler()
			return
		}
	}
	return
}
