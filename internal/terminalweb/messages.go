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
	ReasonUnreachable: 4009, ReasonNotResponding: 4010, ReasonRefused: 4011, ReasonKey: 4012,
}

// CloseIdentityChanged ends a desktop before it starts: the server showed
// another certificate than the approved one, which only an administrator can
// settle. The close text is "identity-changed".
const CloseIdentityChanged websocket.StatusCode = 4020

// Desktop messages and bytes a browser's messages may carry each second. The
// page sends at most one pointer move and one wheel step per display frame,
// plus a graphics acknowledgement per drawn frame: about 540 a second on a
// 240 Hz screen while moving and scrolling, about 1060 on a 500 Hz one. A
// browser past the budget waits for the next second (the socket's own flow
// control holds the rest); it is slowed, never ended, so a fast screen cannot
// cut a desktop.
const (
	desktopMessagesPerSecond = 2048
	desktopBytesPerSecond    = 256 * 1024
	// A browser that stops reading for this long ends the desktop.
	desktopWriteWait = 10 * time.Second
)

// messageEnd is why a desktop ended: the session's cause, else the stream's
// own word. When the stream's word is "refused", the stream names what.
func messageEnd(ctx context.Context, stream MessageStream) (Reason, Refusal) {
	var cause Reason
	if errors.As(context.Cause(ctx), &cause) && reasons[cause] {
		return cause, Refusal{}
	}
	r := stream.Reason()
	if !reasons[r] {
		return "", Refusal{}
	}
	if s, ok := stream.(RefusingStream); ok && r == ReasonRefused {
		if refusal, named := s.Refusal(); named {
			return r, refusal
		}
	}
	return r, Refusal{}
}

// RelayMessages relays an ALREADY authorized desktop socket to its stream.
// The caller owns origin, session, CSRF, the lease and admission, and has
// already written the stream's first message. admit is asked about each
// browser message before it is passed on; false ends the desktop. Only
// binary messages within MaxMessage pass; anything else ends it as
// "refused". Past the per-second budget the relay waits for the next second
// before reading on. Cancellation closes both sides, says why, and
// joins both directions.
//
// It returns the reason the page was told, and for "refused" which side sent
// what, in fixed words (Refusal), so the caller can write it to the journal.
func RelayMessages(ctx context.Context, conn *websocket.Conn, stream MessageStream, admit func([]byte) bool) (Reason, Refusal) {
	if ctx == nil || conn == nil || stream == nil || admit == nil {
		if conn != nil {
			_ = conn.CloseNow()
		}
		if stream != nil {
			_ = stream.Close()
		}
		return "", Refusal{}
	}
	session := ctx
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	defer conn.CloseNow()
	defer stream.Close()
	conn.SetReadLimit(MaxMessage)
	closed := make(chan struct{})
	// Set before closed is closed, read after: the page's reason and, for a
	// refusal, what.
	var told Reason
	var refusal Refusal
	context.AfterFunc(ctx, func() {
		defer close(closed)
		_ = stream.Close()
		reason, named := messageEnd(session, stream)
		var own Reason
		if errors.As(context.Cause(ctx), &own) && reason == "" {
			reason = own
			if own == ReasonRefused {
				named = browserMessageRefused
			}
		}
		if code, ok := closeCodes[reason]; ok {
			_ = conn.Close(code, string(reason))
			told = reason
		}
		if told == ReasonRefused {
			refusal = named
			if refusal == (Refusal{}) {
				refusal = unknownRefusal
			}
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
		if kind != websocket.MessageBinary || len(data) == 0 {
			cancel(ReasonRefused)
			break
		}
		if time.Since(start) >= time.Second {
			start, count, size = time.Now(), 0, 0
		}
		count++
		size += len(data)
		if count > desktopMessagesPerSecond || size > desktopBytesPerSecond {
			// Past the budget: this message, and everything behind it, waits
			// for the next second.
			if !waitFor(ctx, time.Until(start.Add(time.Second))) {
				break
			}
			start, count, size = time.Now(), 1, len(data)
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
	return told, refusal
}

// waitFor waits d, or until ctx ends; it reports whether d passed.
func waitFor(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	wait := time.NewTimer(d)
	defer wait.Stop()
	select {
	case <-wait.C:
		return true
	case <-ctx.Done():
		return false
	}
}
