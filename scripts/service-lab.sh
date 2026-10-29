#!/bin/sh
# Only disposable CI: synthetic state/accounts/units, no production credentials.
set -eu
test "$(uname -m)" = x86_64
test "$(cat /proc/1/comm)" = systemd
test -f /sys/fs/cgroup/cgroup.controllers
build="$(mktemp -d /tmp/keybash-service-build.XXXXXX)"
mutation="$(mktemp -d /tmp/keybash-service-mutation.XXXXXX)"
case "${build}" in /tmp/keybash-service-build.*) ;; *) exit 1 ;; esac
case "${mutation}" in /tmp/keybash-service-mutation.*) ;; *) exit 1 ;; esac
cp internal/sshtransport/process_linux_amd64.go "${mutation}/launcher.original"
restore_source() {
  cp "${mutation}/launcher.original" internal/sshtransport/process_linux_amd64.go
  cmp "${mutation}/launcher.original" internal/sshtransport/process_linux_amd64.go
}
trap 'restore_source; sudo -n rm -rf -- "${build}"; rm -rf -- "${mutation}"' EXIT
chmod 755 "${build}"
for bin in keybash keybash-ssh-manager keybash-ssh-worker keybash-service-check keybash-service-plan; do
  CGO_ENABLED=0 go build -trimpath -o "${build}/${bin}" "./cmd/${bin}"
done
go test -c -tags=sshprocesslab,browserlab,servicelab -o "${build}/service.test" ./internal/sshtransport
sudo -n chown -R root:root "${build}"
sudo -n chmod 555 "${build}/service.test"
run_service() {
  sudo -n env -i KEYBASH_SERVICE_BUILD="${build}" "${build}/service.test" -test.run='^TestKeybashSystemdServiceBoundary$' -test.timeout=3m -test.v
}
run_service
# Ignoring the dedicated identity must be detected from the actual live child,
# not merely from rendered arguments or a configured property.
python3 - <<'PY'
from pathlib import Path
p=Path('internal/sshtransport/process_linux_amd64.go')
s=p.read_text(); old='func sandboxSSHArgs(parentNS string, uid, gid uint32) []string {'
assert s.count(old)==1
p.write_text(s.replace(old,old+'\n uid, gid = 65534, 65534'))
PY
CGO_ENABLED=0 go build -trimpath -o "${mutation}/manager" ./cmd/keybash-ssh-manager
sudo -n install -o root -g root -m 555 "${mutation}/manager" "${build}/keybash-ssh-manager"
if run_service > "${mutation}/identity.log" 2>&1; then
  echo 'service identity mutation escaped its assertion' >&2; exit 1
fi
grep -q 'dedicated worker identity lost' "${mutation}/identity.log"
echo 'Actual service worker identity mutation failed its intended assertion'
restore_source
CGO_ENABLED=0 go build -trimpath -o "${mutation}/manager" ./cmd/keybash-ssh-manager
sudo -n install -o root -g root -m 555 "${mutation}/manager" "${build}/keybash-ssh-manager"
run_service

# The source installer on this same runner, after the lab above has removed
# its units and accounts: install, refusals, uninstall and mutations.
sh scripts/install-lab.sh
