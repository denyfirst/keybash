package terminalweb

import (
	"context"
	"errors"
	"time"

	"github.com/coder/websocket"
)

// Reason names, with one fixed word the pages have a message for, why a
// relayed session ended. It is either the cause a session's context was
// cancelled with, or what a stream that ended by itself reports. Nothing else
// reaches the page: no remote text, and no word outside this list.
type Reason string

func (r Reason) Error() string { return "session ended: " + string(r) }

const (
	ReasonIdle          Reason = "idle"           // Keybash's idle limit signed the person out
	ReasonExpired       Reason = "expired"        // the sign-in reached its absolute life
	ReasonSignedOut     Reason = "signed-out"     // the sign-in ended for another reason
	ReasonAccessChanged Reason = "access-changed" // the server, the connection or the access changed
	ReasonCredentials   Reason = "credentials"    // the server refused the saved user name or password
	ReasonAccount       Reason = "account"        // the server refused the account itself
	ReasonTakenOver     Reason = "taken-over"     // another connection took over the remote session
	ReasonRemoteEnded   Reason = "remote-ended"   // the remote computer ended or signed out the session
	ReasonUnreachable   Reason = "unreachable"    // the server could not be reached or refused the connection
	ReasonNotResponding Reason = "not-responding" // the remote side stopped responding
	ReasonRefused       Reason = "refused"        // Keybash ended a stream that sent what it does not accept
)

var reasons = map[Reason]bool{ReasonIdle: true, ReasonExpired: true, ReasonSignedOut: true, ReasonAccessChanged: true,
	ReasonCredentials: true, ReasonAccount: true, ReasonTakenOver: true, ReasonRemoteEnded: true,
	ReasonUnreachable: true, ReasonNotResponding: true, ReasonRefused: true}

// A Reasoned stream can say why it ended by itself.
type Reasoned interface{ Reason() Reason }

// endReason prefers the session's cause, which also explains why the stream
// stopped; a stream's own word counts only when the session did not end it.
func endReason(ctx context.Context, stream Stream) Reason {
	var cause Reason
	if errors.As(context.Cause(ctx), &cause) && reasons[cause] {
		return cause
	}
	if r, ok := stream.(Reasoned); ok && reasons[r.Reason()] {
		return r.Reason()
	}
	return ""
}

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
	// The reason is read from the caller's context, never from the relay's
	// own: a stream that stops the moment its session ends can make run end
	// the relay's context before the session's cause reaches it.
	session := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer conn.CloseNow()
	defer stream.Close()
	conn.SetReadLimit(32768)
	// Whatever ends the session stops the remote side first, then says why on
	// the socket for at most a second, then closes it. run cancels ctx on every
	// way out, so this always runs, and Relay waits for it.
	closed := make(chan struct{})
	context.AfterFunc(ctx, func() {
		defer close(closed)
		_ = stream.Close()
		if reason := endReason(session, stream); reason != "" {
			say, done := context.WithTimeout(context.Background(), time.Second)
			_ = conn.Write(say, websocket.MessageText, []byte(`{"type":"ended","reason":"`+string(reason)+`"}`))
			done()
		}
		_ = conn.CloseNow()
	})
	run(ctx, cancel, conn, stream, 0, creditTimeout)
	<-closed
}
