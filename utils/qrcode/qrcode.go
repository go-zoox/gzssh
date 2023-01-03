package qrcode

import (
	"io"
	"os"

	"github.com/mdp/qrterminal"
)

type QRCode struct {
	io.Reader

	Text string

	ch chan []byte
}

func New(text string) *QRCode {
	q := &QRCode{
		Text: text,
		ch:   make(chan []byte),
	}

	go q.Generate()

	return q
}

func (q *QRCode) Generate() {
	qrcodeImage := newQRCOdeWriter(q.ch)

	qrterminalCfg := qrterminal.Config{
		Level:     qrterminal.L,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 1,
		// Writer:    qrcodeImage,
	}
	qrterminalCfg.Writer = qrcodeImage

	go qrterminal.GenerateWithConfig(q.Text, qrterminalCfg)
}

func (q *QRCode) Read(p []byte) (n int, err error) {
	n = copy(p, <-q.ch)
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

type QRCodeWriter struct {
	io.Writer

	ch chan []byte
}

func newQRCOdeWriter(ch chan []byte) *QRCodeWriter {
	return &QRCodeWriter{
		ch: ch,
	}
}

func (q *QRCodeWriter) Write(p []byte) (n int, err error) {
	// fmt.Println("write p:", len(p))
	// if len(p) == 0 {
	// 	q.ch <- nil
	// 	return 0, nil
	// }

	q.ch <- p
	return len(p), nil
}

// func (q *QRCodeWriter) Read(p []byte) (n int, err error) {
// 	n = copy(p, <-q.ch)

// 	// done
// 	if n == 1 && p[0] == '\n' {
// 		fmt.Println("done 1")
// 		return 0, io.EOF
// 	}
// 	if n == 0 {
// 		fmt.Println("done 2")
// 		return 0, io.EOF
// 	}

// 	fmt.Println("done 3")
// 	return n, nil
// }
