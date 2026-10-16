#!/bin/sh
# Isolated CI manager, never a root public gateway or a product installation.
set -eu
lab="$(mktemp -d /tmp/keybash-ssh-process.XXXXXX)"
build="$(mktemp -d /tmp/keybash-ssh-build.XXXXXX)"
case "${lab}" in /tmp/keybash-ssh-process.*) ;; *) exit 1 ;; esac
case "${build}" in /tmp/keybash-ssh-build.*) ;; *) exit 1 ;; esac
cp internal/sshtransport/terminal.go "${build}/terminal.original"
cp internal/sshtransport/process_linux_amd64.go "${build}/launcher.original"
restore_sources() {
  cp "${build}/terminal.original" internal/sshtransport/terminal.go
  cp "${build}/launcher.original" internal/sshtransport/process_linux_amd64.go
  cmp "${build}/terminal.original" internal/sshtransport/terminal.go
  cmp "${build}/launcher.original" internal/sshtransport/process_linux_amd64.go
}
trap 'restore_sources; sudo -n rm -rf -- "${lab}"; rm -rf -- "${build}"' EXIT
CGO_ENABLED=0 go build -trimpath -o "${lab}/worker" ./cmd/keybash-ssh-worker
go test -c -race -tags=sshprocesslab,browserlab -o "${lab}/lab.test" ./internal/sshtransport
sudo -n chown root:root "${lab}" "${lab}/worker" "${lab}/lab.test"
sudo -n chmod 755 "${lab}"
sudo -n chmod 555 "${lab}/worker" "${lab}/lab.test"
node_bin="$(dirname "$(command -v node)")"
run_manager() {
  sudo -n env -i PATH="${node_bin}:/usr/bin:/bin" PLAYWRIGHT_BROWSERS_PATH="${HOME}/.cache/ms-playwright" KEYBASH_SSH_WORKER="${lab}/worker" \
    "${lab}/$1" "-test.run=$2" -test.timeout=2m -test.v
}
build_worker() {
  CGO_ENABLED=0 go build -trimpath -o "${build}/worker" ./cmd/keybash-ssh-worker
  sudo -n install -o root -g root -m 555 "${build}/worker" "${lab}/worker"
}
run_manager lab.test '^TestSSHProcess'

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
