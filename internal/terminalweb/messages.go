package terminalweb

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// MessageStream is a desktop whose RDP client runs in the browser (ADR 0008,
// docs/BROWSER-RDP-PAGE.md): whole binary messages each way, at most
// MaxMessage bytes, and the proxy's word when it ends by itself.
type MessageStream interface {
	ReadMessage() ([]byte, error)
	WriteMessage([]byte) error
	Reason() Reason
	Close() error // Must unblock ReadMessage and WriteMessage.
}

// MaxMessage is the largest message either way: the proxy's own frame.
const MaxMessage = 64 * 1024

// A browser desktop ends with a WebSocket close whose code names the reason
// and whose text is the reason's word; the page has a message for each.
// IronRDP's socket carries RDP only, so a JSON notice cannot reach the page.
var closeCodes = map[Reason]websocket.StatusCode{
	ReasonIdle: 4001, ReasonExpired: 4002, ReasonSignedOut: 4003, ReasonAccessChanged: 4004,
	ReasonCredentials: 4005, ReasonAccount: 4006, ReasonTakenOver: 4007, ReasonRemoteEnded: 4008,
	ReasonUnreachable: 4009, ReasonNotResponding: 4010, ReasonRefused: 4011,
}

// CloseIdentityChanged ends a desktop before it starts: the server showed
// another certificate than the approved one, which only an administrator can
// settle. The close text is "identity-changed".
const CloseIdentityChanged websocket.StatusCode = 4020

// CloseCode is the close a reason ends a browser desktop with.
func CloseCode(r Reason) (websocket.StatusCode, bool) {
	code, ok := closeCodes[r]
	return code, ok
}

// Desktop messages a browser may send each second: the same budget as a
// terminal's input (inputFramesPerSecond, inputBytesPerSecond). A dragged
// window sends input and graphics acknowledgements each display frame.
const (
	desktopMessagesPerSecond = inputFramesPerSecond
	desktopBytesPerSecond    = inputBytesPerSecond
	// A browser that stops reading for this long ends the desktop.
	desktopWriteWait = 10 * time.Second
)

func messageEndReason(ctx context.Context, stream MessageStream) Reason {
	var cause Reason
	if errors.As(context.Cause(ctx), &cause) && reasons[cause] {
		return cause
	}
	if r := stream.Reason(); reasons[r] {
		return r
	}
	return ""
}

// RelayMessages relays an ALREADY authorized desktop socket to its stream.
// The caller owns origin, session, CSRF, the lease and admission, and has
// already written the stream's first message. admit is asked about each
// browser message before it is passed on; false ends the desktop. Only
// binary messages within MaxMessage and the per-second budget pass; anything
// else ends it as "refused". Cancellation closes both sides, says why, and
// joins both directions.
func RelayMessages(ctx context.Context, conn *websocket.Conn, stream MessageStream, admit func([]byte) bool) {
	if ctx == nil || conn == nil || stream == nil || admit == nil {
		if conn != nil {
			_ = conn.CloseNow()
		}
		if stream != nil {
			_ = stream.Close()
		}
		return
	}
	session := ctx
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	defer conn.CloseNow()
	defer stream.Close()
	conn.SetReadLimit(MaxMessage)
	closed := make(chan struct{})
	context.AfterFunc(ctx, func() {
		defer close(closed)
		_ = stream.Close()
		reason := messageEndReason(session, stream)
		var own Reason
		if errors.As(context.Cause(ctx), &own) && reason == "" {
			reason = own
		}
		if code, ok := closeCodes[reason]; ok {
			_ = conn.Close(code, string(reason))
		}
		_ = conn.CloseNow()
	})
	// Not ctx for reads and writes: the library closes the socket the moment
	// their context ends, before the close above could say why. The close
	// above ends both instead.
	quiet := context.WithoutCancel(ctx)
	var joined sync.WaitGroup
	joined.Add(1)
	go func() {
		defer joined.Done()
		defer cancel(nil)
		for {
			message, err := stream.ReadMessage()
			if err != nil || len(message) == 0 || len(message) > MaxMessage {
				return
			}
			write, stop := context.WithTimeout(quiet, desktopWriteWait)
			err = conn.Write(write, websocket.MessageBinary, message)
			stop()
			if err != nil {
				return
			}
		}
	}()
	start, count, size := time.Now(), 0, 0
	for {
		kind, data, err := conn.Read(quiet)
		if err != nil {
			cancel(nil)
			break
		}
		if time.Since(start) >= time.Second {
			start, count, size = time.Now(), 0, 0
		}
		count++
		size += len(data)
		if kind != websocket.MessageBinary || len(data) == 0 || count > desktopMessagesPerSecond || size > desktopBytesPerSecond {
			cancel(ReasonRefused)
			break
		}
		if !admit(data) {
			cancel(nil)
			break
		}
		if stream.WriteMessage(data) != nil {
			cancel(nil)
			break
		}
	}
	joined.Wait()
	<-closed
}
