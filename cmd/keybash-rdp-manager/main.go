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
	"github.com/denyfirst/keybash/internal/rdplab"
)

func main() {
	var config rdplab.ManagerConfig
	var digest, runtimeDigest string
	var uid, gid, workerUID, workerGID uint64
	var catalog string
	flag.StringVar(&config.SocketPath, "socket", "", "root-owned private Unix seqpacket socket path")
	flag.StringVar(&config.WorkerPath, "worker", "", "root-owned static RDP worker image")
	flag.StringVar(&config.Runtime, "runtime", "", "root-owned minimal RDP runtime tree")
	flag.StringVar(&runtimeDigest, "runtime-sha256", "", "complete runtime inventory digest")
	flag.StringVar(&digest, "worker-sha256", "", "administrator-approved image digest")
	flag.Uint64Var(&uid, "gateway-uid", 0, "dedicated unprivileged gateway UID")
	flag.Uint64Var(&gid, "gateway-gid", 0, "dedicated unprivileged gateway primary GID")
	flag.Uint64Var(&workerUID, "worker-uid", 0, "dedicated worker UID; omit both for legacy lab identity")
	flag.Uint64Var(&workerGID, "worker-gid", 0, "dedicated worker GID")
	flag.StringVar(&catalog, "config", "", "same root-owned operator catalog as gateway; optional legacy default")
	flag.Parse()
	decoded, err := hex.DecodeString(digest)
	runtimeHash, re := hex.DecodeString(runtimeDigest)
	if flag.NArg() != 0 || catalog == "" || re != nil || len(runtimeHash) != sha256.Size || err != nil || len(decoded) != sha256.Size || uid == 0 || gid == 0 || uid > 2147483647 || gid > 2147483647 || workerUID > 2147483647 || workerGID > 2147483647 || workerUID == 0 || workerGID == 0 {
		fmt.Fprintln(os.Stderr, "invalid manager configuration")
		os.Exit(1)
	}
	copy(config.WorkerDigest[:], decoded)
	copy(config.RuntimeDigest[:], runtimeHash)
	config.GatewayUID, config.GatewayGID = uint32(uid), uint32(gid)
	config.WorkerUID, config.WorkerGID = uint32(workerUID), uint32(workerGID)
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
	if rdplab.ServeRDPManager(ctx, config) != nil {
		fmt.Fprintln(os.Stderr, "RDP manager unavailable")
		os.Exit(1)
	}
}
