package rdplab

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func validNativePlan(t *testing.T) nativePlan {
	t.Helper()
	plan, err := newNativePlan(labIdentity(t), "synthetic-user", "synthetic-password")
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func nativeArgumentNames() instruction {
	return append(instruction{"args", "VERSION_1_5_0"}, strings.Fields(nativeSchema)...)
}

func TestNativePlanEnforcesNLAChannelsAndRedactsCredentials(t *testing.T) {
	p := validNativePlan(t)
	names := nativeArgumentNames()
	args, err := p.arguments(names)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for i, name := range names[2:] {
		values[name] = args[i+2]
	}
	for k, v := range map[string]string{"security": "nla", "ignore-cert": "false", "cert-tofu": "false", "cert-fingerprints": "", "disable-auth": "false", "enable-drive": "false", "enable-printing": "false", "disable-audio": "true", "static-channels": "", "gateway-hostname": "", "recording-path": "", "remote-app": "", "initial-program": "", "preconnection-blob": "", "hostname": "127.0.0.1", "port": "3390", "password": p.password, "username": p.user} {
		if values[k] != v {
			t.Fatalf("unsafe native parameter: %s", k)
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		formatted := fmt.Sprintf(verb, p)
		if strings.Contains(formatted, p.user) || strings.Contains(formatted, p.password) {
			t.Fatal("native plan formatting exposed credential")
		}
	}
	for _, p := range []nativePlan{{}, {identity: labIdentity(t), user: "user", password: ""}, {identity: labIdentity(t), user: "user\n", password: "pass"}, {identity: labIdentity(t), user: "user", password: "p\x00"}, {identity: labIdentity(t), user: "user", password: strings.Repeat("a", 4097)}} {
		if _, err := p.arguments(names); err != errNative {
			t.Fatal("invalid native credentials accepted")
		}
	}
}

func TestNativeArgumentsRejectUnknownDuplicateMissingAndVersion(t *testing.T) {
	plan := validNativePlan(t)
	valid := nativeArgumentNames()
	for _, change := range []func(instruction) instruction{func(i instruction) instruction { i[1] = "VERSION_1_0_0"; return i }, func(i instruction) instruction { i[2] = "unknown-target-option"; return i }, func(i instruction) instruction { i[3] = i[2]; return i }, func(i instruction) instruction { return i[:len(i)-1] }} {
		if _, err := plan.arguments(change(append(instruction(nil), valid...))); err != errNative {
			t.Fatal("unsafe schema accepted")
		}
	}
	// Reordering known arguments is valid; values must track names, not offsets.
	reordered := append(instruction(nil), valid...)
	reordered[2], reordered[3] = reordered[3], reordered[2]
	args, err := plan.arguments(reordered)
	if err != nil || args[2] != "3390" || args[3] != "127.0.0.1" {
		t.Fatal("valid reordered schema refused/misbound")
	}
}

func TestNativeHandshakeStrictSchemaReadyAndContextCleanup(t *testing.T) {
	plan := validNativePlan(t)
	for _, bad := range []bool{false, true} {
		client, server := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan bool, 1)
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			selectRDP, err := readInstruction(reader)
			if err != nil || !bytes.Equal([]byte(strings.Join(selectRDP, ",")), []byte("select,rdp")) {
				done <- false
				return
			}
			args := nativeArgumentNames()
			if bad {
				args[2] = "bad"
			}
			if writeBoundedInstruction(server, args, 128) != nil {
				done <- false
				return
			}
			if bad {
				var b [1]byte
				n, _ := server.Read(b[:])
				done <- n == 0
				return
			}
			for range 5 {
				if _, err := readInstruction(reader); err != nil {
					done <- false
					return
				}
			}
			connect, err := readBoundedInstruction(reader, 128)
			if err != nil || len(connect) != len(args) {
				done <- false
				return
			}
			if writeInstruction(server, instruction{"ready", "private-session-id"}) != nil {
				done <- false
				return
			}
			var b [1]byte
			n, _ := server.Read(b[:])
			done <- n == 0
		}()
		stream, err := nativeConnect(ctx, client, plan)
		if bad {
			if err != errNative || stream != nil {
				t.Fatal("unsafe native handshake accepted")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			stream.close()
			stream.close()
		}
		cancel()
		select {
		case ok := <-done:
			if !ok {
				t.Fatal("handshake/cleanup evidence failed")
			}
		case <-time.After(time.Second):
			t.Fatal("native transport leaked")
		}
	}
}

func TestNativeStreamRefusesUnsolicitedStreamsAndBoundsOutput(t *testing.T) {
	for _, op := range []string{"file", "pipe", "argv", "audio", "video", "require", "select", "connect", "error", "ack blob"} {
		client, server := net.Pipe()
		stream := &nativeStream{raw: client, reader: bufio.NewReader(client), stop: func() bool { return true }}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			_ = writeInstruction(server, instruction{op, "private remote diagnostic"})
		}()
		if in, err := stream.next(); err != errNative || in != nil {
			t.Fatal("unsolicited native instruction escaped")
		}
		<-done
	}
	for _, quota := range []string{"bytes", "frames"} {
		client, server := net.Pipe()
		stream := &nativeStream{raw: client, reader: bufio.NewReader(client), stop: func() bool { return true }}
		if quota == "bytes" {
			stream.output = 8*1024*1024 - 1
		} else {
			stream.frames = 8192
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			_ = writeInstruction(server, instruction{"sync", "1"})
		}()
		if in, err := stream.next(); err != errNative || in != nil {
			t.Fatal("native output exceeded quota")
		}
		<-done
	}
	client, server := net.Pipe()
	stream := &nativeStream{raw: client, reader: bufio.NewReader(client), stop: func() bool { return true }}
	defer stream.close()
	go func() { _ = writeInstruction(server, instruction{"sync", "123"}); _ = server.Close() }()
	if in, err := stream.next(); err != nil || len(in) != 2 || in[1] != "123" {
		t.Fatal("valid native output refused")
	}
}
