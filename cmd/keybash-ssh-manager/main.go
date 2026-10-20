// The laboratory manager is separate from the public custody gateway. No
// service installation, target configuration or credential input is provided.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/denyfirst/keybash/internal/operatorconfig"
	"github.com/denyfirst/keybash/internal/sshtransport"
)

func main() {
	var config sshtransport.ManagerConfig
	var digest string
	var uid, gid, workerUID, workerGID uint64
	var catalog string
	flag.StringVar(&config.SocketPath, "socket", "", "root-owned private Unix seqpacket socket path")
	flag.StringVar(&config.Worker.Path, "worker", "", "root-owned static SSH worker image")
	flag.StringVar(&digest, "worker-sha256", "", "administrator-approved image digest")
	flag.Uint64Var(&uid, "gateway-uid", 0, "dedicated unprivileged gateway UID")
	flag.Uint64Var(&gid, "gateway-gid", 0, "dedicated unprivileged gateway primary GID")
	flag.Uint64Var(&workerUID, "worker-uid", 0, "dedicated worker UID; omit both for legacy lab identity")
	flag.Uint64Var(&workerGID, "worker-gid", 0, "dedicated worker GID")
	flag.StringVar(&catalog, "config", "", "same root-owned operator catalog as gateway; optional legacy default")
	flag.Parse()
	decoded, err := hex.DecodeString(digest)
	if flag.NArg() != 0 || err != nil || len(decoded) != sha256.Size || uid == 0 || gid == 0 || uid > 2147483647 || gid > 2147483647 || workerUID > 2147483647 || workerGID > 2147483647 || (workerUID == 0) != (workerGID == 0) {
		fmt.Fprintln(os.Stderr, "invalid manager configuration")
		os.Exit(1)
	}
	copy(config.Worker.Digest[:], decoded)
	config.GatewayUID, config.GatewayGID = uint32(uid), uint32(gid)
	config.Worker.UID, config.Worker.GID = uint32(workerUID), uint32(workerGID)
	if catalog != "" {
		snapshot, err := operatorconfig.LoadCatalog(catalog)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid manager configuration")
			os.Exit(1)
		}
		config.MaxSessions = snapshot.Capacity.Total
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if sshtransport.ServeSSHManager(ctx, config) != nil {
		fmt.Fprintln(os.Stderr, "SSH manager unavailable")
		os.Exit(1)
	}
}
