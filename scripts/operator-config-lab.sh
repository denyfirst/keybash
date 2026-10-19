#!/bin/sh
# Root is confined to synthetic file/UID/CLI tests; this installs no service.
set -eu
lab="$(mktemp -d /tmp/keybash-operator-config.XXXXXX)"
case "${lab}" in /tmp/keybash-operator-config.*) ;; *) exit 1 ;; esac
cp internal/operatorconfig/catalog.go "${lab}/catalog.original"
cp internal/operatorconfig/load_linux.go "${lab}/load.original"
restore_sources() {
  cp "${lab}/catalog.original" internal/operatorconfig/catalog.go
  cp "${lab}/load.original" internal/operatorconfig/load_linux.go
  cmp "${lab}/catalog.original" internal/operatorconfig/catalog.go
  cmp "${lab}/load.original" internal/operatorconfig/load_linux.go
}
trap 'restore_sources; sudo -n rm -rf -- "${lab}"' EXIT
CGO_ENABLED=0 go build -trimpath -o "${lab}/keybash" ./cmd/keybash
go test -c -race -o "${lab}/catalog.test" ./internal/operatorconfig
go test -c -race -o "${lab}/cli.test" ./cmd/keybash
sudo -n chown root:root "${lab}" "${lab}/keybash" "${lab}/catalog.test" "${lab}/cli.test"
sudo -n chmod 755 "${lab}"
sudo -n chmod 555 "${lab}/keybash" "${lab}/catalog.test" "${lab}/cli.test"
run_catalog() {
  sudo -n env -i "${lab}/catalog.test" -test.run='^TestOperatorCatalog' -test.timeout=40s -test.v
}
run_cli() {
  sudo -n env -i KEYBASH_OPERATOR_BINARY="${lab}/keybash" "${lab}/cli.test" -test.run='^TestOperatorCatalogCLI' -test.timeout=60s -test.v
}
run_catalog
run_cli
for mutation in file-owner-bypass file-owner-refuse directory-owner-bypass symlink-bypass; do
  python3 - "${mutation}" <<'PY'
from pathlib import Path
import sys
p = Path('internal/operatorconfig/load_linux.go')
s = p.read_text()
old, new = {
 'file-owner-bypass': ('before.Uid != 0', 'false'),
 'file-owner-refuse': ('before.Uid != 0', 'true'),
 'directory-owner-bypass': ('stat.Uid == 0', 'true'),
 'symlink-bypass': ('|unix.O_NOFOLLOW', ''),
}[sys.argv[1]]
assert s.count(old) == (2 if sys.argv[1] == 'symlink-bypass' else 1)
p.write_text(s.replace(old, new))
PY
  go test -c -race -o "${lab}/mutant.test" ./internal/operatorconfig
  sudo -n install -o root -g root -m 555 "${lab}/mutant.test" "${lab}/catalog.test"
  if run_catalog > "${lab}/mutation.log" 2>&1; then
    echo 'operator file mutation escaped its assertion' >&2; exit 1
  fi
  assertion='unsafe catalog file accepted'
  if test "${mutation}" = file-owner-refuse; then assertion='valid root-owned catalog refused'; fi
  grep -q "${assertion}" "${lab}/mutation.log"
  echo "Operator ${mutation} mutation failed its intended assertion"
  restore_sources
done
go test -c -race -o "${lab}/restored.test" ./internal/operatorconfig
sudo -n install -o root -g root -m 555 "${lab}/restored.test" "${lab}/catalog.test"
run_catalog
run_cli
