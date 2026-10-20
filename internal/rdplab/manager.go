package rdplab

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/denyfirst/keybash/internal/identity"
	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// ManagerConfig is trusted offline operator configuration, never IPC input.
// Runtime is a read-only root-owned minimal filesystem with its own loader and
// library closure. RuntimeDigest binds its complete canonical file inventory.
type ManagerConfig struct {
	SocketPath, WorkerPath, Runtime string
	WorkerDigest, RuntimeDigest     [sha256.Size]byte
	GatewayUID, GatewayGID          uint32
	WorkerUID, WorkerGID            uint32
	MaxSessions                     int
}

func (c ManagerConfig) valid() bool {
	return c.GatewayUID > 0 && c.GatewayGID > 0 && c.WorkerUID > 0 && c.WorkerGID > 0 &&
		c.GatewayUID <= 2147483647 && c.GatewayGID <= 2147483647 && c.WorkerUID <= 2147483647 && c.WorkerGID <= 2147483647 &&
		c.GatewayUID != 65534 && c.WorkerUID != 65534 && c.GatewayGID != 65534 && c.WorkerGID != 65534 &&
		c.GatewayUID != c.WorkerUID && c.GatewayGID != c.WorkerGID &&
		c.WorkerDigest != [sha256.Size]byte{} && c.RuntimeDigest != [sha256.Size]byte{} &&
		c.MaxSessions >= 1 && c.MaxSessions <= sessionlimits.MaxTotal
}

type ManagerWorker struct{ SocketPath string }

func (w ManagerWorker) OpenRDP(ctx context.Context, request identity.RDPRequest) (terminalweb.Stream, error) {
	if request.Target == nil {
		return nil, errNative
	}
	pin, err := NewIdentity(request.Target.Hostname(), request.Certificate)
	if err != nil {
		return nil, errNative
	}
	return w.open(ctx, request.Target, pin, request.Username, request.Password)
}

func (w ManagerWorker) open(ctx context.Context, target *targetguard.NamedTarget, pin *Identity, user, password string) (terminalweb.Stream, error) {
	if target == nil || pin == nil || target.Hostname() != pin.name {
		return nil, errNative
	}
	return w.openDial(ctx, target.DialContext, pin, user, password)
}

// Only package _test.go callers can replace this guarded dial for a fixture.
func (w ManagerWorker) openDial(ctx context.Context, dial func(context.Context) (net.Conn, error), pin *Identity, user, password string) (terminalweb.Stream, error) {
	plan, err := newNativePlan(pin, user, password)
	if ctx == nil || ctx.Err() != nil || dial == nil || err != nil {
		return nil, errNative
	}
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := connectRDPManager(ctx, setup, w.SocketPath, dial, pin)
	if err != nil {
		return nil, errNative
	}
	native, err := nativeConnect(ctx, raw, plan)
	if err != nil {
		_ = raw.Close()
		return nil, errNative
	}
	return newViewerStream(native), nil
}

func (ManagerConfig) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "[RDP manager configuration]")
}

// Keep numeric worker arguments canonical; no namespace/path argument is ever
// used as a file path or command by the child.
func ParseWorkerID(s string) (uint32, error) {
	v, e := strconv.ParseUint(s, 10, 31)
	if e != nil || v == 0 || v == 65534 || strconv.FormatUint(v, 10) != s {
		return 0, errNative
	}
	return uint32(v), nil
}
