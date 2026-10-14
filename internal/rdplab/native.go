package rdplab

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var errNative = errors.New("native RDP lab refused")

// private lab policy: no browser-selected parameters or production entry point.
type nativePlan struct {
	identity       *Identity
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
		"disable-copy": "false", "disable-paste": "false", "normalize-clipboard": "preserve",
		"resize-method": "display-update", "client-name": "Keybash-lab", "disable-gfx": "true", "force-lossless": "true",
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
	raw    net.Conn
	reader *bufio.Reader
	stop   func() bool
	once   sync.Once
	output int
	frames int
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
	stream := &nativeStream{raw: raw, reader: bufio.NewReader(raw)}
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
	s.once.Do(func() { s.stop(); _ = s.raw.Close() })
}

func (s *nativeStream) next() (instruction, error) {
	in, err := readInstruction(s.reader)
	if err != nil {
		s.close()
		return nil, errNative
	}
	for _, v := range in {
		s.output += len(v)
	}
	s.frames++
	if s.output > 8*1024*1024 || s.frames > 8192 {
		s.close()
		return nil, errNative
	}
	// No files, pipes, audio/video, mutable args, credential prompts or remote
	// messages escape to a future viewer. There is no browser tunnel yet.
	allowed := false
	for _, op := range strings.Fields("ack blob cfill clip close copy cursor dispose distort end identity img lfill line move name path pop push rect reset shade size start sync transfer transform clipboard") {
		allowed = allowed || op == in[0]
	}
	if !allowed {
		s.close()
		return nil, errNative
	}
	return in, nil
}
