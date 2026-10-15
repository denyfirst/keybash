package terminalweb

import (
	"context"

	"github.com/coder/websocket"
)

// Relay transports an ALREADY authorized socket/stream. The caller owns HTTP
// origin, MFA, CSRF, ownership and one-use admission. Cancellation closes both
// sides and joins the bounded relay workers. It adds no lab bootstrap cookie.
func Relay(ctx context.Context, conn *websocket.Conn, stream Stream) {
	if ctx == nil || conn == nil || stream == nil {
		if conn != nil {
			_ = conn.CloseNow()
		}
		if stream != nil {
			_ = stream.Close()
		}
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer conn.CloseNow()
	defer stream.Close()
	conn.SetReadLimit(32768)
	stop := context.AfterFunc(ctx, func() { _ = conn.CloseNow(); _ = stream.Close() })
	defer stop()
	run(ctx, cancel, conn, stream, 8*1024*1024)
}
