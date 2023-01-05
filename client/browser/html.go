package browser

import (
	"encoding/json"
	"fmt"

	"github.com/go-zoox/logger"
	"github.com/go-zoox/zoox"
)

func RenderXTerm(data zoox.H) string {
	jd, err := json.Marshal(data)
	if err != nil {
		logger.Errorf("failed json marshal data in render XTerm: %v", err)
	}

	return fmt.Sprintf(`<!doctype html>
	<html>
		<head>
			<title>Web Terminal</title>
			<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm/css/xterm.css" />
			<script src="https://cdn.jsdelivr.net/npm/xterm/lib/xterm.js"></script>
			<script src="https://cdn.jsdelivr.net/npm/xterm-addon-attach"></script>
			<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit"></script>
			<style>
				* {
					padding: 0;
					margin: 0;
					box-sizing: border-box;
				}

				body {
					margin: 8px;
					background-color: #000;
				}

				#terminal {
					width: calc(100vw - 16px);
					height: calc(100vh - 16px);
				}
			</style>
		</head>
		<body>
			<div id="terminal"></div>
			<script>
				var config = %s;

				var url = new URL(window.location.href);
				var query = new URLSearchParams(location.search);
				var protocol = url.protocol === 'https:' ? 'wss' : 'ws';

				if (query.get('title') && document.querySelector('title')) {
					document.querySelector('title').innerText = query.get('title');
				}

				var ws = new WebSocket(protocol + '://' + url.host + config.wsPath  );
				var term = new Terminal({
					fontFamily: 'Menlo, Monaco, "Courier New", monospace',
					fontWeight: 400,
					fontSize: 14,
					// rows: 200,
				});
				var attachAddon = new AttachAddon.AttachAddon(ws);
				var fitAddon = new FitAddon.FitAddon();
				var msgType = {
					MsgData: '1',
					MsgResize: '2',
				};

				term.loadAddon(attachAddon);
				term.loadAddon(fitAddon);
		
				term.onResize(({ cols, rows }) => {
					// nodejs
					// ws.send(JSON.stringify([
					// 	'resize',
					// 	{ cols, rows },
					// ]));

					// go
					ws.send(msgType.MsgResize + JSON.stringify({ cols, rows }));
				});

 				term.onKey((event) => {
            ws.send(msgType.MsgData + event.key);
        })

				ws.onopen = () => {
					term.open(document.getElementById('terminal'));
					fitAddon.fit();

					if (!!config.welcomeMessage) {
						term.write(config.welcomeMessage + " \r\n")
					} else {
						term.write("Welcome to GzSSH Client in Web Browser \r\n")
					}

					term.focus();
				}

				ws.onclose = () => {
					terminal.write("\r\nGzSSH Client Quit!")
					
					if (confirm('WebSocket Disconnect, Try to reconnect ?')) {
						window.location.reload();
					}
				}

				window.addEventListener("resize", () =>{
          fitAddon.fit()
        }, false)
			</script>
		</body>
	</html>`, jd)
}
