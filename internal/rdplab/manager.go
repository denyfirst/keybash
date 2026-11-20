package rdplab

import (
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"

	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/targetguard"
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

// ManagerWorker opens desktops through the RDP manager at SocketPath: each one
// is Keybash's RDP proxy in its own sandbox (OpenBrowserRDP).
type ManagerWorker struct{ SocketPath string }

// identityFor takes the rules from the target, never from the certificate: a
// server at a literal address is identified by its exact certificate, a server
// with a DNS name also by that name.
func identityFor(target *targetguard.NamedTarget, certificate []byte) (*Identity, error) {
	if target.Literal() {
		return NewExactIdentity(certificate)
	}
	return NewIdentity(target.Hostname(), certificate)
}

func (ManagerConfig) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "[RDP manager configuration]")
}

// ParseWorkerID keeps numeric worker arguments canonical; no namespace/path argument is ever
// used as a file path or command by the child.
func ParseWorkerID(s string) (uint32, error) {
	v, e := strconv.ParseUint(s, 10, 31)
	if e != nil || v == 0 || v == 65534 || strconv.FormatUint(v, 10) != s {
		return 0, errNative
	}
	return uint32(v), nil
}
