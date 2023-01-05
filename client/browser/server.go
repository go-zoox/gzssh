package browser

import (
	"github.com/go-zoox/zoox"
	"github.com/go-zoox/zoox/defaults"
)

type Server interface {
	Run(addr string, wsHandler zoox.WsGorillaHandlerFunc) error
}

type server struct {
}

func NewServer() Server {
	return &server{}
}

func Serve(addr string, wsHandler zoox.WsGorillaHandlerFunc) error {
	s := NewServer()
	return s.Run(addr, wsHandler)
}

func (s *server) Run(addr string, wsHandler zoox.WsGorillaHandlerFunc) error {
	app := defaults.Application()

	app.WebSocket("/ws", func(ctx *zoox.Context, client *zoox.WebSocketClient) {
		wsHandler(ctx, client.GetGorillaWebsocketConn())
	})
	// app.WebSocketGorilla("/ws", wsHandler)

	// var upgrader = websocket.Upgrader{
	// 	ReadBufferSize:  1024,
	// 	WriteBufferSize: 1024 * 10,
	// 	CheckOrigin: func(r *http.Request) bool {
	// 		return true
	// 	},
	// }
	// app.Get("/ws", func(ctx *zoox.Context) {
	// 	wsConn, err := upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
	// 	if err != nil {
	// 		ctx.JSON(400, zoox.H{
	// 			"code":    4000001,
	// 			"message": err.Error(),
	// 		})

	// 		return
	// 	}
	// 	defer wsConn.Close()

	// 	wsHandler(ctx, wsConn)
	// })

	app.Get("/", func(ctx *zoox.Context) {
		ctx.HTML(200, RenderXTerm(zoox.H{
			"wsPath": "/ws",
			// "welcomeMessage": "custom welcome message",
		}))
	})

	return app.Run(addr)
}
