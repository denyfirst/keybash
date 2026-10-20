#!/bin/sh
# Isolated CI manager, never a root public gateway or a product installation.
set -eu
lab="$(mktemp -d /tmp/keybash-ssh-process.XXXXXX)"
build="$(mktemp -d /tmp/keybash-ssh-build.XXXXXX)"
case "${lab}" in /tmp/keybash-ssh-process.*) ;; *) exit 1 ;; esac
case "${build}" in /tmp/keybash-ssh-build.*) ;; *) exit 1 ;; esac
cp internal/sshtransport/terminal.go "${build}/terminal.original"
cp internal/sshtransport/process_linux_amd64.go "${build}/launcher.original"
cp internal/sshtransport/manager_linux_amd64.go "${build}/manager.original"
cp cmd/keybash-ssh-manager/main.go "${build}/manager-cli.original"
restore_sources() {
  cp "${build}/terminal.original" internal/sshtransport/terminal.go
  cp "${build}/launcher.original" internal/sshtransport/process_linux_amd64.go
  cmp "${build}/terminal.original" internal/sshtransport/terminal.go
  cmp "${build}/launcher.original" internal/sshtransport/process_linux_amd64.go
  cp "${build}/manager.original" internal/sshtransport/manager_linux_amd64.go
  cmp "${build}/manager.original" internal/sshtransport/manager_linux_amd64.go
  cp "${build}/manager-cli.original" cmd/keybash-ssh-manager/main.go
  cmp "${build}/manager-cli.original" cmd/keybash-ssh-manager/main.go
}
trap 'restore_sources; sudo -n rm -rf -- "${lab}"; rm -rf -- "${build}"' EXIT
CGO_ENABLED=0 go build -trimpath -o "${lab}/worker" ./cmd/keybash-ssh-worker
CGO_ENABLED=0 go build -trimpath -o "${lab}/manager" ./cmd/keybash-ssh-manager
go test -c -race -tags=sshprocesslab,browserlab -o "${lab}/lab.test" ./internal/sshtransport
sudo -n chown root:root "${lab}" "${lab}/worker" "${lab}/manager" "${lab}/lab.test"
sudo -n chmod 755 "${lab}"
sudo -n chmod 555 "${lab}/worker" "${lab}/manager" "${lab}/lab.test"
node_bin="$(dirname "$(command -v node)")"
run_manager() {
  sudo -n env -i PATH="${node_bin}:/usr/bin:/bin" PLAYWRIGHT_BROWSERS_PATH="${HOME}/.cache/ms-playwright" KEYBASH_SSH_WORKER="${lab}/worker" \
    "${lab}/$1" "-test.run=$2" -test.timeout=2m -test.v
}
build_worker() {
  CGO_ENABLED=0 go build -trimpath -o "${build}/worker" ./cmd/keybash-ssh-worker
  sudo -n install -o root -g root -m 555 "${build}/worker" "${lab}/worker"
}
build_manager() {
  CGO_ENABLED=0 go build -trimpath -o "${build}/manager" ./cmd/keybash-ssh-manager
  sudo -n install -o root -g root -m 555 "${build}/manager" "${lab}/manager"
}
run_manager lab.test '^TestSSHProcess'
run_manager lab.test '^TestSSHManager'

# Configured capacity must replace the old constant in both the library and
# the standalone manager. Overflow and default-only regressions must be caught.
for mutation in overflow default; do
  python3 - "${mutation}" <<'PY'
from pathlib import Path
import sys
p=Path('internal/sshtransport/manager_linux_amd64.go')
s=p.read_text()
old,new = ('make(chan struct{}, capacity)','make(chan struct{}, capacity+1)') if sys.argv[1]=='overflow' else ('managerCapacity(config.MaxSessions)','managerCapacity(0)')
assert s.count(old)==1
p.write_text(s.replace(old,new))
PY
  go test -c -race -tags=sshprocesslab,browserlab -o "${build}/mutant.test" ./internal/sshtransport
  sudo -n install -o root -g root -m 555 "${build}/mutant.test" "${lab}/mutant.test"
  if run_manager mutant.test '^TestSSHManagerConfiguredCapacity$' > "${build}/capacity-mutation.log" 2>&1; then
    echo 'manager capacity mutation escaped its intended assertion' >&2; exit 1
  fi
  assertion='configured manager overflowed capacity'
  if test "${mutation}" = default; then assertion='configured manager refused within capacity'; fi
  grep -q "${assertion}" "${build}/capacity-mutation.log"
  echo "SSH manager capacity ${mutation} mutation failed its intended assertion"
  restore_sources
done
python3 - <<'PY'
from pathlib import Path
p=Path('cmd/keybash-ssh-manager/main.go')
s=p.read_text();old='config.MaxSessions = snapshot.Capacity.Total'
assert s.count(old)==1
p.write_text(s.replace(old,old+' * 0'))
PY
build_manager
if run_manager lab.test '^TestSSHManagerCLIConfiguredCapacity$' > "${build}/cli-capacity-mutation.log" 2>&1; then
  echo 'CLI capacity mutation escaped its intended assertion' >&2; exit 1
fi
grep -q 'configured manager refused within capacity' "${build}/cli-capacity-mutation.log"
echo 'SSH manager CLI capacity mutation failed its intended assertion'
restore_sources
build_manager

# Kernel-credential admission must accept only the configured nonroot gateway.
# Both compiling mutations exercise actual manager + unprivileged subprocesses.
for direction in bypass refuse; do
  python3 - "${direction}" <<'PY'
from pathlib import Path
import sys
p=Path('internal/sshtransport/manager_linux_amd64.go')
s=p.read_text();old='err != nil || cred.Uid != config.GatewayUID || cred.Gid != config.GatewayGID'
assert s.count(old)==1
new='err != nil' if sys.argv[1]=='bypass' else 'true || '+old
# Keep the peer value used in the bypass mutant without changing its behavior.
if sys.argv[1]=='bypass': new='err != nil || cred.Uid == 4294967295'
p.write_text(s.replace(old,new))
PY
  go test -c -race -tags=sshprocesslab,browserlab -o "${build}/mutant.test" ./internal/sshtransport
  sudo -n install -o root -g root -m 555 "${build}/mutant.test" "${lab}/mutant.test"
  pattern='^TestSSHManagerRejectsWrongPeer$'
  assertion='wrong gateway peer accepted'
  if test "${direction}" = refuse; then
    pattern='^TestSSHManagerUnprivilegedGateway$'
    assertion='valid unprivileged gateway refused'
  fi
  if run_manager mutant.test "${pattern}" > "${build}/manager-mutation.log" 2>&1; then
    echo 'manager credential mutation escaped its intended assertion' >&2; exit 1
  fi
  grep -q "${assertion}" "${build}/manager-mutation.log"
  echo "SSH manager ${direction} mutation failed its intended assertion"
  restore_sources
done

for direction in bypass refuse; do
  python3 - "${direction}" <<'PY'
from pathlib import Path
import sys
p=Path('internal/sshtransport/manager_linux_amd64.go')
s=p.read_text();old='tcp := int(files[0].Fd())'
assert s.count(old)==1
value='true' if sys.argv[1]=='bypass' else 'false'
p.write_text(s.replace(old,'if len(files) == 3 { return '+value+' }; '+old))
PY
  go test -c -race -tags=sshprocesslab,browserlab -o "${build}/mutant.test" ./internal/sshtransport
  sudo -n install -o root -g root -m 555 "${build}/mutant.test" "${lab}/mutant.test"
  if run_manager mutant.test '^TestSSHManagerDescriptorKinds$' > "${build}/descriptor-mutation.log" 2>&1; then
    echo 'manager descriptor mutation escaped its intended assertion' >&2; exit 1
  fi
  assertion='unsafe manager descriptors accepted'
  if test "${direction}" = refuse; then assertion='valid manager descriptors refused'; fi
  grep -q "${assertion}" "${build}/descriptor-mutation.log"
  echo "SSH manager descriptor ${direction} mutation failed its intended assertion"
  restore_sources
done

# Both host-pin directions are sabotaged in the ACTUAL child image. A failure
# must contain its intended assertion, not a build, sandbox or timeout failure.
python3 - <<'PY'
from pathlib import Path
p=Path('internal/sshtransport/terminal.go')
s=p.read_text();old='if !bytes.Equal(pin, key.Marshal()) {'
assert s.count(old)==1
p.write_text(s.replace(old,'if false && !bytes.Equal(pin, key.Marshal()) {'))
PY
build_worker
if run_manager lab.test '^TestSSHProcessChangedPinNeverAuthenticates$' > "${build}/pin-bypass.log" 2>&1; then
  echo 'pin bypass escaped its intended assertion' >&2; exit 1
fi
grep -q 'changed process host pin accepted' "${build}/pin-bypass.log"
echo 'Actual SSH child pin bypass failed its intended assertion'
restore_sources
python3 - <<'PY'
from pathlib import Path
p=Path('internal/sshtransport/terminal.go')
s=p.read_text();old='if !bytes.Equal(pin, key.Marshal()) {'
assert s.count(old)==1
p.write_text(s.replace(old,'if true || !bytes.Equal(pin, key.Marshal()) {'))
PY
build_worker
if run_manager lab.test '^TestSSHProcessIsolatedAuthenticationAndRevocation$' > "${build}/pin-refuse.log" 2>&1; then
  echo 'pin over-refusal escaped its intended assertion' >&2; exit 1
fi
grep -q 'valid isolated worker refused' "${build}/pin-refuse.log"
echo 'Actual SSH child over-refusal failed its intended assertion'
restore_sources
build_worker

# Removing either required isolation layer must prevent the positive worker
# from starting; original worker code refuses before reading session material.
for layer in network seccomp; do
  python3 - "${layer}" <<'PY'
from pathlib import Path
import sys
p=Path('internal/sshtransport/process_linux_amd64.go')
s=p.read_text()
old='"--unshare-net", ' if sys.argv[1]=='network' else '"--seccomp", "5", '
assert s.count(old)==1
p.write_text(s.replace(old,''))
PY
  go test -c -race -tags=sshprocesslab,browserlab -o "${build}/mutant.test" ./internal/sshtransport
  sudo -n install -o root -g root -m 555 "${build}/mutant.test" "${lab}/mutant.test"
  if run_manager mutant.test '^TestSSHProcessIsolatedAuthenticationAndRevocation$' > "${build}/isolation.log" 2>&1; then
    echo 'missing isolation escaped its intended assertion' >&2; exit 1
  fi
  grep -q 'valid isolated worker refused' "${build}/isolation.log"
  echo "Removing SSH ${layer} isolation failed its intended assertion"
  restore_sources
done
run_manager lab.test '^TestSSHProcess'
run_manager lab.test '^TestSSHManager'
