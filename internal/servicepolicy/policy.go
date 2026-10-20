// Package servicepolicy renders an offline, source-only systemd SSH lab plan.
// It never installs, enables or starts a unit. Host administration remains trusted.
package servicepolicy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var ErrPolicy = errors.New("service policy refused")

type Config struct {
	GatewayUID, GatewayGID            uint32
	WorkerUID, WorkerGID              uint32
	WorkerDigest                      string
	RDPWorkerDigest, RDPRuntimeDigest string
	CPUPercent                        uint64
	MemoryMiB                         uint64
	Tasks                             uint64
}

func Default() Config { return Config{CPUPercent: 200, MemoryMiB: 1024, Tasks: 512} }

func (c Config) HasRDP() bool { return c.RDPWorkerDigest != "" && c.RDPRuntimeDigest != "" }
func validDigest(s string) bool {
	d, e := hex.DecodeString(s)
	return e == nil && len(d) == 32 && s == strings.ToLower(s) && s != strings.Repeat("0", 64)
}
func (c Config) Valid() bool {
	if (c.RDPWorkerDigest != "" || c.RDPRuntimeDigest != "") && (!validDigest(c.RDPWorkerDigest) || !validDigest(c.RDPRuntimeDigest)) {
		return false
	}
	for _, id := range []uint32{c.GatewayUID, c.GatewayGID, c.WorkerUID, c.WorkerGID} {
		if id < 1 || id > 2147483647 || id == 65534 {
			return false
		}
	}
	digest, err := hex.DecodeString(c.WorkerDigest)
	return c.GatewayUID != c.WorkerUID && c.GatewayGID != c.WorkerGID &&
		err == nil && len(digest) == 32 && c.WorkerDigest == strings.ToLower(c.WorkerDigest) && c.WorkerDigest != strings.Repeat("0", 64) &&
		c.CPUPercent >= 10 && c.CPUPercent <= 6400 && c.MemoryMiB >= 256 && c.MemoryMiB <= 1048576 && c.Tasks >= 128 && c.Tasks <= 32768
}

// Render accepts only integers and a canonical digest. No path, command, unit
// name, environment or directive can be injected into the fixed templates.
func Render(c Config) (map[string]string, error) {
	if !c.Valid() {
		return nil, ErrPolicy
	}
	args := fmt.Sprintf("--gateway-uid=%d --gateway-gid=%d --worker-uid=%d --worker-gid=%d --worker-digest=%s --cpu-percent=%d --memory-mib=%d --tasks=%d", c.GatewayUID, c.GatewayGID, c.WorkerUID, c.WorkerGID, c.WorkerDigest, c.CPUPercent, c.MemoryMiB, c.Tasks)
	if c.HasRDP() {
		args += " --rdp-worker-digest=" + c.RDPWorkerDigest + " --rdp-runtime-digest=" + c.RDPRuntimeDigest
	}
	common := `Slice=keybash.slice
Type=exec
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ProtectControlGroups=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
RestrictSUIDSGID=yes
LockPersonality=yes
LimitCORE=0
LimitNOFILE=4096
KillMode=control-group
TimeoutStopSec=10s
SendSIGKILL=yes
OOMPolicy=kill
Restart=no
StandardInput=null
StandardOutput=null
StandardError=journal
`
	gateway := fmt.Sprintf(`[Unit]
Description=Keybash SSH laboratory gateway
BindsTo=keybash-ssh-manager.service
After=keybash-ssh-manager.service
PartOf=keybash-ssh-manager.service

[Service]
User=%d
Group=%d
%sCapabilityBoundingSet=
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryDenyWriteExecute=yes
ReadWritePaths=/var/lib/keybash
InaccessiblePaths=-/etc/keybash/worker-private
ExecStartPre=/usr/local/libexec/keybash/keybash-service-check --role=gateway %s
ExecStart=/usr/local/libexec/keybash/keybash serve-ssh-lab --data=/var/lib/keybash --key-file=/etc/keybash/keys/instance.key --listen=127.0.0.1:8443 --tls-cert=/etc/keybash/tls/cert.pem --tls-key=/etc/keybash/tls/key.pem --config=/etc/keybash/targets.json --ssh-manager=/run/keybash-manager/control.sock

[Install]
WantedBy=multi-user.target
`, c.GatewayUID, c.GatewayGID, common, args)
	manager := fmt.Sprintf(`[Unit]
Description=Keybash fixed SSH worker manager

[Service]
User=root
Group=root
%sPrivateNetwork=yes
# Bubblewrap uses netlink for private loopback setup and mknod for private /dev.
RestrictAddressFamilies=AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SYS_PTRACE CAP_NET_ADMIN CAP_MKNOD CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_KILL
AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_SETPCAP
RuntimeDirectory=keybash-manager
RuntimeDirectoryMode=0755
InaccessiblePaths=-/var/lib/keybash -/etc/keybash/keys -/etc/keybash/tls
ExecStartPre=/usr/local/libexec/keybash/keybash-service-check --role=manager %s
ExecStart=/usr/local/libexec/keybash/keybash-ssh-manager --socket=/run/keybash-manager/control.sock --worker=/usr/local/libexec/keybash/keybash-ssh-worker --worker-sha256=%s --gateway-uid=%d --gateway-gid=%d --worker-uid=%d --worker-gid=%d --config=/etc/keybash/targets.json

[Install]
WantedBy=multi-user.target
`, common, args, c.WorkerDigest, c.GatewayUID, c.GatewayGID, c.WorkerUID, c.WorkerGID)
	files := map[string]string{
		"keybash.slice": fmt.Sprintf(`[Unit]
Description=Keybash aggregate resource boundary

[Slice]
CPUAccounting=yes
MemoryAccounting=yes
TasksAccounting=yes
CPUQuota=%d%%
CPUQuotaPeriodSec=100ms
MemoryMax=%dM
MemorySwapMax=0
TasksMax=%d
`, c.CPUPercent, c.MemoryMiB, c.Tasks),
		"keybash-gateway.service":     gateway,
		"keybash-ssh-manager.service": manager,
		"keybash.conf":                fmt.Sprintf("g keybash-gateway %d\ng keybash-worker %d\nu keybash-gateway %d:%d \"Keybash gateway\" /nonexistent /usr/sbin/nologin\nu keybash-worker %d:%d \"Keybash SSH worker\" /nonexistent /usr/sbin/nologin\n", c.GatewayGID, c.WorkerGID, c.GatewayUID, c.GatewayGID, c.WorkerUID, c.WorkerGID),
	}
	if c.HasRDP() {
		for _, key := range []string{"BindsTo=", "After=", "PartOf="} {
			gateway = strings.ReplaceAll(gateway, key+"keybash-ssh-manager.service", key+"keybash-ssh-manager.service keybash-rdp-manager.service")
		}
		gateway = strings.ReplaceAll(gateway, "serve-ssh-lab", "serve-remote-lab")
		gateway = strings.ReplaceAll(gateway, "--ssh-manager=/run/keybash-manager/control.sock", "--ssh-manager=/run/keybash-manager/control.sock --rdp-manager=/run/keybash-rdp-manager/control.sock")
		files["keybash-gateway.service"] = gateway
		rdp := strings.ReplaceAll(manager, "fixed SSH worker manager", "fixed RDP worker manager")
		rdp = strings.ReplaceAll(rdp, "keybash-manager", "keybash-rdp-manager")
		rdp = strings.ReplaceAll(rdp, "--role=manager", "--role=rdp-manager")
		rdp = strings.ReplaceAll(rdp, "RestrictAddressFamilies=AF_UNIX AF_NETLINK", "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET")
		begin := strings.Index(rdp, "ExecStart=")
		end := strings.Index(rdp[begin:], "\n") + begin
		rdp = rdp[:begin] + fmt.Sprintf("ExecStart=/usr/local/libexec/keybash/keybash-rdp-manager --socket=/run/keybash-rdp-manager/control.sock --worker=/usr/local/libexec/keybash/keybash-rdp-worker --worker-sha256=%s --runtime=/usr/local/lib/keybash/rdp --runtime-sha256=%s --gateway-uid=%d --gateway-gid=%d --worker-uid=%d --worker-gid=%d --config=/etc/keybash/targets.json", c.RDPWorkerDigest, c.RDPRuntimeDigest, c.GatewayUID, c.GatewayGID, c.WorkerUID, c.WorkerGID) + rdp[end:]
		files["keybash-rdp-manager.service"] = rdp
	}
	return files, nil
}

// validateState also runs on synthetic snapshots. Runtime reads only the fixed
// kernel hierarchy, not a caller-supplied proc/sysfs path.
func validateState(c Config, role, membership string, files map[string]string) error {
	unit := map[string]string{"gateway": "keybash-gateway.service", "manager": "keybash-ssh-manager.service", "rdp-manager": "keybash-rdp-manager.service"}[role]
	if !c.Valid() || role == "rdp-manager" && !c.HasRDP() || unit == "" || membership != "0::/keybash.slice/"+unit+"\n" {
		return ErrPolicy
	}
	parse := func(s string) (uint64, bool) {
		n, err := strconv.ParseUint(s, 10, 64)
		return n, err == nil && strconv.FormatUint(n, 10) == s
	}
	cpu := strings.Fields(files["cpu.max"])
	if len(cpu) != 2 {
		return ErrPolicy
	}
	quota, q := parse(cpu[0])
	period, p := parse(cpu[1])
	// Bound before multiplication, including fabricated/overflow snapshots.
	if !q || !p || period < 1000 || period > 1000000 || quota == 0 || quota > 64000000 || quota*100 != period*c.CPUPercent {
		return ErrPolicy
	}
	for file, expected := range map[string]uint64{"memory.max": c.MemoryMiB << 20, "memory.swap.max": 0, "pids.max": c.Tasks} {
		value, ok := parse(strings.TrimSuffix(files[file], "\n"))
		if !ok || value != expected {
			return ErrPolicy
		}
	}
	return nil
}
