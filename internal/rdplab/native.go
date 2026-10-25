package rdplab

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

var errNative = errors.New("native RDP lab refused")

// private lab policy: no browser-selected parameters or production entry point.
type nativePlan struct {
	identity       *Identity
	workspace      bool
	user, password string
}

func (p nativePlan) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, "[RDP lab plan redacted]") }

func newNativePlan(identity *Identity, user, password string) (nativePlan, error) {
	if identity == nil || len(identity.der) == 0 || identity.roots == nil || identity.name == "" ||
		len(user) == 0 || len(user) > 128 || len(password) == 0 || len(password) > 4096 || !utf8.ValidString(password) || strings.ContainsRune(password, 0) {
		return nativePlan{}, errNative
	}
	for _, c := range user {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-@", c)) {
			return nativePlan{}, errNative
		}
	}
	return nativePlan{identity: identity, user: user, password: password}, nil
}

// Exact Guacamole 1.6.0 schema without SSH/SFTP support. New arguments require
// an explicit review; defaults cannot silently add a new destination/channel.
const nativeSchema = "hostname port timeout domain username password width height dpi initial-program color-depth disable-audio enable-printing printer-name enable-drive drive-name drive-path create-drive-path disable-download disable-upload console console-audio server-layout security ignore-cert cert-tofu cert-fingerprints disable-auth remote-app remote-app-dir remote-app-args static-channels client-name enable-wallpaper enable-theming enable-font-smoothing enable-full-window-drag enable-desktop-composition enable-menu-animations disable-bitmap-caching disable-offscreen-caching disable-glyph-caching disable-gfx preconnection-id preconnection-blob timezone recording-path recording-name recording-exclude-output recording-exclude-mouse recording-exclude-touch recording-include-keys create-recording-path recording-write-existing resize-method enable-audio-input enable-touch read-only gateway-hostname gateway-port gateway-domain gateway-username gateway-password load-balance-info disable-copy disable-paste wol-send-packet wol-mac-addr wol-broadcast-addr wol-udp-port wol-wait-time force-lossless normalize-clipboard"

func (p nativePlan) arguments(args instruction) (instruction, error) {
	if _, err := newNativePlan(p.identity, p.user, p.password); err != nil {
		return nil, errNative
	}
	expected := strings.Fields(nativeSchema)
	if len(args) != len(expected)+2 || args[0] != "args" || args[1] != "VERSION_1_5_0" {
		return nil, errNative
	}
	known := make(map[string]bool, len(expected))
	for _, name := range expected {
		known[name] = true
	}
	values := map[string]string{
		"hostname": "127.0.0.1", "port": "3390", "timeout": "10", "username": p.user, "password": p.password,
		"width": "1024", "height": "768", "dpi": "96", "color-depth": "32", "security": "nla",
		"ignore-cert": "false", "cert-tofu": "false", "disable-auth": "false", "disable-audio": "true",
		"enable-printing": "false", "enable-drive": "false", "create-drive-path": "false",
		"disable-download": "true", "disable-upload": "true", "console": "false", "console-audio": "false",
		"enable-audio-input": "false", "enable-touch": "false", "recording-include-keys": "false",
		"create-recording-path": "false", "recording-write-existing": "false", "wol-send-packet": "false",
		// Native clipboard stays off until the bounded text adapter and browser
		// actions are connected and measured; the separate codec is not enough.
		"disable-copy": "true", "disable-paste": "true", "normalize-clipboard": "preserve",
		// Fixed lab viewport. Dynamic display channels need their own native
		// callback/resize evidence before enabling them in a browser workspace.
		"resize-method": "", "client-name": "Keybash-lab", "disable-gfx": "true", "force-lossless": "true",
	}
	if p.workspace {
		values["disable-copy"] = "false"
		values["disable-paste"] = "false"
		values["resize-method"] = "display-update"
		values["client-name"] = "Keybash"
	}
	result := instruction{"connect", "VERSION_1_5_0"}
	for _, name := range args[2:] {
		if !known[name] {
			return nil, errNative
		}
		known[name] = false
		result = append(result, values[name])
	}
	return result, nil
}

type nativeStream struct {
	raw       net.Conn
	ctx       context.Context
	closed    atomic.Bool
	workspace bool
	reader    *bufio.Reader
	stop      func() bool
	once      sync.Once
	output    pacer // owned by the single reader, like next itself
	frames    pacer
	clock     func() time.Time    // nil means time.Now; tests supply a fake
	sleep     func(time.Duration) // nil means time.Sleep
	failure   atomic.Value        // fixed private string classifications, never remote diagnostic text
}

func (s *nativeStream) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}
func (s *nativeStream) wait(d time.Duration) bool {
	sleep := time.Sleep
	if s.sleep != nil {
		sleep = s.sleep
	}
	return pause(d, s.revoked, sleep)
}

func nativeConnect(ctx context.Context, raw net.Conn, plan nativePlan) (*nativeStream, error) {
	if raw == nil {
		return nil, errNative
	}
	ok := false
	defer func() {
		if !ok {
			_ = raw.Close()
		}
	}()
	if ctx == nil {
		return nil, errNative
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := newNativePlan(plan.identity, plan.user, plan.password); err != nil {
		return nil, errNative
	}
	stream := &nativeStream{ctx: ctx, workspace: plan.workspace, raw: raw, reader: bufio.NewReader(raw)}
	stream.stop = context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer func() {
		if !ok {
			stream.stop()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	if d, has := ctx.Deadline(); has && d.Before(deadline) {
		deadline = d
	}
	if raw.SetDeadline(deadline) != nil || writeInstruction(raw, instruction{"select", "rdp"}) != nil {
		return nil, errNative
	}
	args, err := readBoundedInstruction(stream.reader, 128)
	if err != nil {
		return nil, errNative
	}
	connect, err := plan.arguments(args)
	if err != nil {
		return nil, errNative
	}
	for _, in := range []instruction{{"size", "1024", "768", "96"}, {"audio"}, {"video"}, {"image", "image/png"}, {"timezone", "UTC"}} {
		if writeInstruction(raw, in) != nil {
			return nil, errNative
		}
	}
	if writeBoundedInstruction(raw, connect, 128) != nil {
		return nil, errNative
	}
	ready, err := readInstruction(stream.reader)
	if err != nil || len(ready) != 2 || ready[0] != "ready" || len(ready[1]) == 0 || len(ready[1]) > 128 {
		return nil, errNative
	}
	// ready is only guacd session creation, NOT RDP authentication evidence.
	if raw.SetDeadline(time.Time{}) != nil {
		return nil, errNative
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ok = true
	return stream, nil
}

func (s *nativeStream) close() {
	if s == nil {
		return
	}
	s.closed.Store(true)
	s.once.Do(func() { s.stop(); _ = s.raw.Close() })
}

func (s *nativeStream) revoked() bool {
	if s == nil || s.closed.Load() || s.ctx != nil && s.ctx.Err() != nil {
		return true
	}
	if lease, ok := s.raw.(interface{ leaseContext() context.Context }); ok {
		ctx := lease.leaseContext()
		return ctx != nil && ctx.Err() != nil
	}
	return false
}

func (s *nativeStream) next() (instruction, error) {
	for {
		if s.revoked() {
			s.close()
			return nil, errNative
		}
		in, err := readInstruction(s.reader)
		if err != nil || s.revoked() {
			s.failure.Store("instruction framing")
			s.close()
			return nil, errNative
		}
		size := 0
		for _, v := range in {
			size += len(v)
		}
		now := s.now()
		byteWait, sized := s.output.reserve(size, nativeByteBurst, nativeBytesPerSecond, now)
		frameWait, counted := s.frames.reserve(1, nativeInstructionBurst, nativeInstructionsPerSec, now)
		if !sized || !counted {
			s.failure.Store("output quota")
			s.close()
			return nil, errNative
		}
		if !s.wait(max(byteWait, frameWait)) {
			s.close()
			return nil, errNative
		}
		// Protocol 1.5 sends owner join/leave notices before native connection
		// setup, plus keepalives. Consume only these exact bounded shapes; never
		// forward their metadata or admit arbitrary remote messages.
		if len(in) == 1 && in[0] == "nop" ||
			in[0] == "msg" && len(in) >= 3 && len(in[2]) > 0 && len(in[2]) <= 128 &&
				(len(in) == 4 && in[1] == "1" && in[3] == "" || len(in) == 3 && in[1] == "2") {
			continue
		}
		if len(in) == 4 && in[0] == "set" && in[2] == "multi-touch" && in[3] == "0" {
			if layer, err := strconv.ParseUint(in[1], 10, 16); err == nil && layer <= 32767 {
				continue // fixed disabled-touch metadata; no arbitrary property setter
			}
		}
		// No files, pipes, audio/video, mutable args, credential prompts or remote
		// messages escape. The private viewer further validates drawing schemas.
		allowed := false
		for _, op := range strings.Fields("ack blob cfill clip close copy cursor dispose distort end identity img lfill line mouse move name path pop push rect reset shade size start sync transfer transform") {
			allowed = allowed || op == in[0]
		}
		allowed = allowed || s.workspace && in[0] == "clipboard"
		if !allowed {
			s.failure.Store("unexpected instruction")
			switch in[0] {
			case "error":
				if len(in) == 3 {
					if status, err := strconv.ParseUint(in[2], 10, 16); err == nil {
						s.failure.Store("native status " + strconv.FormatUint(status, 10))
					}
				}
			case "set":
				s.failure.Store("unsupported drawing property")
			case "msg":
				s.failure.Store("invalid owner notice")
			case "argv":
				s.failure.Store("unexpected parameter request")
			}
			s.close()
			return nil, errNative
		}
		return in, nil
	}
}
