//go:build linux && amd64

package servicepolicy

import (
	"io"
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

func Check(c Config, role string) error {
	if !c.Valid() || role != "gateway" && role != "manager" {
		return ErrPolicy
	}
	for name, ids := range map[string][2]uint32{"keybash-gateway": {c.GatewayUID, c.GatewayGID}, "keybash-worker": {c.WorkerUID, c.WorkerGID}} {
		u, err := user.Lookup(name)
		g, ge := user.LookupGroup(name)
		if err != nil || ge != nil || u.Uid != strconv.FormatUint(uint64(ids[0]), 10) || u.Gid != strconv.FormatUint(uint64(ids[1]), 10) || g.Gid != u.Gid {
			return ErrPolicy
		}
		// Refuse existing numeric identities belonging to another account/group.
		byID, ue := user.LookupId(u.Uid)
		groupID, ge := user.LookupGroupId(g.Gid)
		if ue != nil || ge != nil || byID.Username != name || groupID.Name != name {
			return ErrPolicy
		}
	}
	if role == "manager" && (os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0) ||
		role == "gateway" && (os.Getuid() != int(c.GatewayUID) || os.Geteuid() != int(c.GatewayUID) || os.Getgid() != int(c.GatewayGID) || os.Getegid() != int(c.GatewayGID)) {
		return ErrPolicy
	}
	groups, err := os.Getgroups()
	if err != nil {
		return ErrPolicy
	}
	for _, g := range groups {
		if role == "gateway" && g != int(c.GatewayGID) || role == "manager" && g != 0 {
			return ErrPolicy
		}
	}
	var stat unix.Statfs_t
	if unix.Statfs("/sys/fs/cgroup", &stat) != nil || stat.Type != unix.CGROUP2_SUPER_MAGIC {
		return ErrPolicy
	}
	read := func(path string) (string, error) {
		f, err := os.Open(path) // #nosec G304 -- fixed proc/cgroup paths below; no browser or CLI path input.
		if err != nil {
			return "", ErrPolicy
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || len(raw) > 4096 {
			return "", ErrPolicy
		}
		return string(raw), nil
	}
	membership, err := read("/proc/self/cgroup")
	if err != nil {
		return ErrPolicy
	}
	files := make(map[string]string)
	for _, file := range []string{"cpu.max", "memory.max", "memory.swap.max", "pids.max"} {
		files[file], err = read("/sys/fs/cgroup/keybash.slice/" + file)
		if err != nil {
			return ErrPolicy
		}
	}
	return validateState(c, role, membership, files)
}
