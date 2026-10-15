//go:build browserlab

package identity

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	"golang.org/x/crypto/ssh"
)

const demoRemotePassword = "Synthetic desktop password, no remote account!"

type demoWorker struct{}

// These workers have no dial or process execution path. Catalog addresses are
// inert metadata. They do not implement or claim SSH/RDP authentication.
func (*demoWorker) OpenSSH(ctx context.Context, _ *targetguard.NamedTarget, _ []byte, user string, _ ssh.Signer) (terminalweb.Stream, error) {
	if user != "synthetic-user" || ctx.Err() != nil {
		return nil, errRefused
	}
	a, b := net.Pipe()
	stop := context.AfterFunc(ctx, func() { _ = a.Close(); _ = b.Close() })
	go func() { defer stop(); defer b.Close(); demoTerminal(b) }()
	return fixtureRemoteStream{a}, nil
}

func demoCommand(line string) string {
	switch line {
	case "help":
		return "SIMULATION ONLY. No local or remote shell.\r\nCommands: help, whoami, hostname, pwd, ls, uname, date, echo TEXT, clear, exit\r\n"
	case "whoami":
		return "synthetic-user\r\n"
	case "hostname":
		return "keybash-demo.invalid\r\n"
	case "pwd":
		return "/home/synthetic-user (simulated)\r\n"
	case "ls":
		return "README-demo.txt  no-real-files/\r\n"
	case "uname", "uname -a":
		return "Simulated Linux terminal UI; no operating system attached\r\n"
	case "date":
		return time.Now().UTC().Format(time.RFC3339) + "\r\n"
	case "clear":
		return "\x1b[2J\x1b[H"
	case "":
		return ""
	}
	if strings.HasPrefix(line, "echo ") {
		return strings.TrimPrefix(line, "echo ") + "\r\n"
	}
	return "Demo: command unavailable. Type help. Nothing was executed.\r\n"
}

func demoTerminal(conn net.Conn) {
	if _, err := io.WriteString(conn, "\x1b[36mKEYBASH INTERACTIVE UI DEMO\x1b[0m\r\nSimulation only: no Linux shell, host files or network access.\r\nType help. Try Unicode, selection/copy, paste preview and Ctrl+C.\r\n\r\ndemo@keybash:~$ "); err != nil {
		return
	}
	r := bufio.NewReader(conn)
	line := []rune{}
	for {
		ch, _, err := r.ReadRune()
		if err != nil {
			return
		}
		out := ""
		switch ch {
		case '\r', '\n':
			if string(line) == "exit" {
				_, _ = io.WriteString(conn, "\r\nDemo session closed.\r\n")
				return
			}
			out = "\r\n" + demoCommand(string(line)) + "demo@keybash:~$ "
			line = line[:0]
		case 3:
			line = line[:0]
			out = "^C\r\ndemo@keybash:~$ "
		case 4:
			return
		case 12:
			out = "\x1b[2J\x1b[Hdemo@keybash:~$ " + string(line)
		case 8, 127:
			if len(line) > 0 {
				line = line[:len(line)-1]
				out = "\b \b"
			}
		case 27:
			// Consume a bounded CSI arrow/bracketed-paste marker, never execute
			// or reflect escape sequences from user input.
			if next, err := r.ReadByte(); err != nil || next != '[' {
				return
			}
			for i := 0; i < 16; i++ {
				b, err := r.ReadByte()
				if err != nil {
					return
				}
				if b >= 0x40 && b <= 0x7e {
					break
				}
				if i == 15 {
					return
				}
			}
		default:
			if ch >= 32 && ch != utf8.RuneError && len(line) < 1024 {
				line = append(line, ch)
				out = string(ch)
			}
		}
		if _, err := io.WriteString(conn, out); err != nil {
			return
		}
	}
}

// Only canonical numeric Guacamole input emitted by the existing UI is accepted.
// No generic tunnel, stream/file/clipboard or arbitrary drawing instruction.
func demoInput(raw []byte) ([]string, bool) {
	if len(raw) == 0 || len(raw) > 1024 {
		return nil, false
	}
	text := string(raw)
	parts := []string{}
	for len(parts) < 5 {
		dot := strings.IndexByte(text, '.')
		if dot < 1 || dot > 4 {
			return nil, false
		}
		n, err := strconv.Atoi(text[:dot])
		if err != nil || n < 1 || strconv.Itoa(n) != text[:dot] || n > len(text)-dot-2 {
			return nil, false
		}
		parts = append(parts, text[dot+1:dot+1+n])
		sep := text[dot+1+n]
		text = text[dot+2+n:]
		if sep == ';' {
			if text != "" {
				return nil, false
			}
			break
		}
		if sep != ',' {
			return nil, false
		}
	}
	if text != "" || len(parts) == 0 {
		return nil, false
	}
	limits := []int{}
	switch parts[0] {
	case "key":
		limits = []int{0x1ffffff, 1}
	case "mouse":
		limits = []int{1023, 767, 31}
	case "sync":
		limits = []int{1 << 30}
	case "ack":
		if len(parts) != 4 || parts[2] != "OK" {
			return nil, false
		}
		for _, i := range []int{1, 3} {
			n, err := strconv.Atoi(parts[i])
			if err != nil || n < 0 || n > 1<<30 || strconv.Itoa(n) != parts[i] {
				return nil, false
			}
		}
		return parts, true
	case "nop":
		return parts, len(parts) == 1
	default:
		return nil, false
	}
	if len(parts) != len(limits)+1 {
		return nil, false
	}
	for i, limit := range limits {
		n, err := strconv.Atoi(parts[i+1])
		if err != nil || n < 0 || n > limit || strconv.Itoa(n) != parts[i+1] {
			return nil, false
		}
	}
	return parts, true
}

func demoWire(values ...string) []byte {
	var b strings.Builder
	for i, value := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d.%s", utf8.RuneCountInString(value), value)
	}
	b.WriteByte(';')
	return []byte(b.String())
}

func (*demoWorker) OpenRDP(ctx context.Context, request RDPRequest) (terminalweb.Stream, error) {
	if request.Username != "synthetic-user" || request.Password != demoRemotePassword || ctx.Err() != nil {
		return nil, errRefused
	}
	a, b := net.Pipe()
	stop := context.AfterFunc(ctx, func() { _ = a.Close(); _ = b.Close() })
	s := &demoDesktop{Conn: a, output: make(chan string, 8), done: make(chan struct{})}
	go func() {
		defer stop()
		defer b.Close()
		defer close(s.done)
		if _, err := b.Write(demoWire("size", "0", "1024", "768")); err != nil {
			return
		}
		if !demoImage(b, "TYPE HERE - THIS IS A SIMULATION", true, 1) {
			return
		}
		sequence := 2
		for {
			select {
			case <-ctx.Done():
				return
			case text := <-s.output:
				if !demoImage(b, text, false, sequence) {
					return
				}
				sequence++
			}
		}
	}()
	return s, nil
}

type demoDesktop struct {
	net.Conn
	output chan string
	done   chan struct{}
	text   []rune // sole relay input writer
}

func (*demoDesktop) ReadStderr([]byte) (int, error) { return 0, io.EOF }
func (*demoDesktop) Resize(uint32, uint32) error    { return errRefused }
func (s *demoDesktop) Write(raw []byte) (int, error) {
	parts, ok := demoInput(raw)
	if !ok {
		return 0, errRefused
	}
	text := ""
	if parts[0] == "key" && parts[2] == "1" {
		key, _ := strconv.Atoi(parts[1])
		if key == 0xff08 && len(s.text) > 0 {
			s.text = s.text[:len(s.text)-1]
		} else if key == 0xff0d {
			s.text = nil
		} else if key >= 32 && key < 127 && len(s.text) < 48 {
			s.text = append(s.text, rune(key))
		}
		text = "INPUT: " + string(s.text)
	} else if parts[0] == "mouse" && parts[3] == "1" {
		text = "MOUSE: " + parts[1] + ", " + parts[2]
	}
	if text != "" {
		select {
		case <-s.done:
			return 0, errRefused
		case s.output <- text:
		default:
			return 0, errRefused
		}
	}
	return len(raw), nil
}

func demoImage(w io.Writer, text string, full bool, sequence int) bool {
	width, height, x, y := 920, 150, "52", "320"
	if full {
		width, height, x, y = 1024, 768, "0", "0"
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.RGBA{20, 22, 28, 255}), image.Point{}, draw.Src)
	if full {
		draw.Draw(img, image.Rect(0, 0, width, 6), image.NewUniform(color.RGBA{218, 54, 68, 255}), image.Point{}, draw.Src)
		demoText(img, 52, 70, "KEYBASH / DESKTOP DEMO", 4)
		demoText(img, 52, 150, "SIMULATION - NO WINDOWS OS ATTACHED", 2)
		demoText(img, 52, 200, "CLICK OR TYPE TO TEST KEYBOARD AND MOUSE", 2)
		demoText(img, 52, 240, "BACKSPACE ERASES / ENTER CLEARS", 2)
		demoText(img, 52, 650, "CLIPBOARD AND REMOTE RESIZE ARE DISABLED", 2)
		demoText(img, 52, 690, "LOG OUT OF YOUR ACCOUNT TO CLOSE ALL VIEWS", 2)
		demoText(img, 52, 350, text, 2)
	} else {
		demoText(img, 0, 30, text, 2)
	}
	var encoded bytes.Buffer
	if png.Encode(&encoded, img) != nil {
		return false
	}
	if _, err := w.Write(demoWire("img", "0", "14", "0", "image/png", x, y)); err != nil {
		return false
	}
	data := base64.StdEncoding.EncodeToString(encoded.Bytes())
	for len(data) > 0 {
		n := min(4096, len(data))
		if _, err := w.Write(demoWire("blob", "0", data[:n])); err != nil {
			return false
		}
		data = data[n:]
	}
	_, err := w.Write(append(demoWire("end", "0"), demoWire("sync", strconv.Itoa(sequence))...))
	return err == nil
}

// Tiny fixed bitmap alphabet keeps this synthetic image local and dependency
// free. It is a test picture, not an OS desktop or a product font.
func demoText(img *image.RGBA, x, y int, text string, scale int) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /:-,."
	const glyphs = "0E11111F111111,1E11111E11111E,0F10101010100F,1E11111111111E,1F10101E10101F,1F10101E101010,0F10101711110F,1111111F111111,1F04040404041F,0101010111110E,11121418141211,1010101010101F,111B1515111111,11191513111111,0E11111111110E,1E11111E101010,0E11111115120D,1E11111E141211,0F10100E01011E,1F040404040404,1111111111110E,11111111110A04,11111115151B11,11110A040A1111,11110A04040404,1F01020408101F,0E11131519110E,040C040404040E,0E11010204081F,1E01010E01011E,02060A121F0202,1F10101E01011E,0E10101E11110E,1F010204080808,0E11110E11110E,0E11110F01010E,00000000000000,01010204081010,00040000040000,0000001F000000,00000000000408,00000000000004"
	font := strings.Split(glyphs, ",")
	for _, ch := range strings.ToUpper(text) {
		index := strings.IndexRune(alphabet, ch)
		if index >= 0 {
			for row := 0; row < 7; row++ {
				bits, _ := strconv.ParseUint(font[index][row*2:row*2+2], 16, 8)
				for column := 0; column < 5; column++ {
					if bits&(1<<uint(4-column)) != 0 {
						rect := image.Rect(x+column*scale, y+row*scale, x+(column+1)*scale, y+(row+1)*scale)
						draw.Draw(img, rect, image.NewUniform(color.RGBA{225, 229, 238, 255}), image.Point{}, draw.Src)
					}
				}
			}
		}
		x += 6 * scale
	}
}

func TestDemoInputBoundary(t *testing.T) {
	for _, values := range [][]string{{"key", "97", "1"}, {"mouse", "1023", "767", "1"}, {"sync", "1"}, {"ack", "0", "OK", "0"}, {"nop"}} {
		if _, ok := demoInput(demoWire(values...)); !ok {
			t.Fatal("valid demo input refused")
		}
	}
	for _, raw := range [][]byte{demoWire("clipboard", "0", "text/plain"), demoWire("mouse", "1024", "1", "1"), demoWire("key", "97", "2"), demoWire("key", "01", "1"), []byte("3.key,2.97,1.1;3.nop;"), []byte("3.key,2.97,1.1"), []byte(strings.Repeat("x", 1025))} {
		if _, ok := demoInput(raw); ok {
			t.Fatal("unsafe or malformed demo input accepted")
		}
	}
	if !strings.Contains(demoCommand("help"), "SIMULATION ONLY") || !strings.Contains(demoCommand("echo hello"), "hello") {
		t.Fatal("valid simulated command refused")
	}
	for _, raw := range []string{"powershell", "bash -c id", "cat /etc/passwd", "echo; whoami", "curl https://example.invalid"} {
		if !strings.Contains(demoCommand(raw), "Nothing was executed") {
			t.Fatal("arbitrary demo command accepted")
		}
	}
}

func TestDemoWorkerCancellation(t *testing.T) {
	worker := &demoWorker{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := worker.OpenRDP(ctx, RDPRequest{Username: "synthetic-user", Password: "wrong"}); err == nil {
		t.Fatal("wrong demo credential accepted")
	}
	if _, err := worker.OpenSSH(ctx, nil, nil, "wrong-user", nil); err == nil {
		t.Fatal("wrong demo user accepted")
	}
	stream, err := worker.OpenSSH(ctx, nil, nil, "synthetic-user", nil)
	if err != nil {
		t.Fatal("valid demo user refused")
	}
	defer stream.Close()
	buffer := make([]byte, 2048)
	if n, err := stream.Read(buffer); err != nil || !bytes.Contains(buffer[:n], []byte("Simulation only")) {
		t.Fatal("demo disclosure missing")
	}
	cancel()
	done := make(chan error, 1)
	go func() { _, err := stream.Read(buffer); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled demo stream stayed readable")
		}
	case <-time.After(time.Second):
		t.Fatal("demo cancellation did not release read")
	}
	if _, err := worker.OpenRDP(ctx, RDPRequest{Username: "synthetic-user", Password: demoRemotePassword}); err == nil {
		t.Fatal("canceled demo worker started")
	}
}
