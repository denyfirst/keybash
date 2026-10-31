#!/bin/sh
# CI only, on a disposable runner: builds a stage, checks that the installer
# refuses bad input before changing anything, installs, checks the running
# service end to end, upgrades it (refusals first, a new worker digest, a
# failed upgrade put back, upgrader mutations), refuses a second install,
# uninstalls (keeping data), and runs installer mutations in both directions.
# Removes everything it made.
#   install-lab.sh            SSH only
#   install-lab.sh RUNTIME    also the RDP service, from a scripts/build-rdp-runtime.py tree
# Synthetic secrets only; the installer's secret output is never printed.
set -eu
test "$(cat /proc/1/comm)" = systemd
runtime="${1:-}"
work="$(mktemp -d /tmp/keybash-install-lab.XXXXXX)"
case "${work}" in /tmp/keybash-install-lab.*) ;; *) exit 1 ;; esac
chmod 755 "${work}"
reset_host() {
  sudo -n sh scripts/uninstall.sh >/dev/null 2>&1 || true
  sudo -n rm -rf -- /var/lib/keybash /etc/keybash /var/backups/keybash /run/keybash-upgrade.lock
  for account in keybash-gateway keybash-worker; do
    sudo -n userdel "${account}" 2>/dev/null || true
    sudo -n groupdel "${account}" 2>/dev/null || true
  done
}
trap 'reset_host; sudo -n rm -rf -- "${work}"' EXIT
installed_paths='/usr/local/libexec/keybash /usr/local/lib/keybash /etc/keybash /var/lib/keybash /etc/sysusers.d/keybash.conf /etc/systemd/system/keybash-gateway.service'

stage="${work}/stage"
if test -n "${runtime}"; then
  sh scripts/build-stage.sh "${stage}" --rdp-runtime="${runtime}"
else
  sh scripts/build-stage.sh "${stage}"
fi
"${stage}/bin/keybash-test-tls" --address 127.0.0.1 --output "${work}/tls" >/dev/null
"${stage}/bin/keybash-test-tls" --name other.lan --output "${work}/other-tls" >/dev/null
"${stage}/bin/keybash-test-tls" --name rdp.invalid --output "${work}/rdp-tls" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C '' -f "${work}/host"
hostkey="$(cut -d ' ' -f 1,2 "${work}/host.pub")"
ssh_target="{\"id\":\"$(printf 'a%.0s' $(seq 32))\",\"name\":\"Install lab SSH\",\"protocol\":\"ssh\",\"hostname\":\"ssh.invalid\",\"port\":22,\"addresses\":[\"10.44.0.8\"],\"ssh_host_key\":\"${hostkey}\"}"
rdp_certificate="$(openssl x509 -in "${work}/rdp-tls/cert.pem" -outform DER | base64 -w0)"
rdp_target="{\"id\":\"$(printf 'b%.0s' $(seq 32))\",\"name\":\"Install lab RDP\",\"protocol\":\"rdp\",\"hostname\":\"rdp.invalid\",\"port\":3389,\"addresses\":[\"10.44.0.9\"],\"rdp_certificate\":\"${rdp_certificate}\"}"
printf '{"version":1,"protected_networks":["10.99.0.0/16"],"targets":[%s]}\n' "${ssh_target}" > "${work}/ssh.json"
printf '{"version":1,"protected_networks":["10.99.0.0/16"],"targets":[%s,%s]}\n' "${ssh_target}" "${rdp_target}" > "${work}/mixed.json"
catalog="${work}/ssh.json"
test -z "${runtime}" || catalog="${work}/mixed.json"
base="--stage=${stage} --catalog=${catalog} --tls-cert=${work}/tls/cert.pem --tls-key=${work}/tls/key.pem"

# refused LABEL INSTALLER ARGS...: refused with the preflight message, and the
# host is exactly as before.
refused() {
  label="$1" installer="$2"
  shift 2
  if sudo -n sh "${installer}" "$@" >"${work}/refused.out" 2>"${work}/refused.err"; then
    echo "install accepted: ${label}" >&2
    return 1
  fi
  if ! grep -q '^install refused: ' "${work}/refused.err" || grep -q 'Install stopped after it had changed' "${work}/refused.err"; then
    echo "install did not refuse before changing the host: ${label}" >&2
    return 1
  fi
  for path in ${installed_paths}; do
    if test -e "${path}"; then
      echo "refused install left ${path}: ${label}" >&2
      return 1
    fi
  done
  echo "Refused before any change: ${label} ($(cut -c1-80 "${work}/refused.err"))"
}
# shellcheck disable=SC2086 # base holds fixed, space-free lab paths
install_ok() {
  if ! sudo -n sh "$1" ${base} >"${work}/install.out" 2>"${work}/install.err"; then
    cat "${work}/install.err" >&2
    sudo -n journalctl --no-pager -n 60 -u keybash-gateway.service -u keybash-ssh-manager.service -u keybash-rdp-manager.service >&2 || true
    return 1
  fi
}

if sh scripts/install.sh ${base} >/dev/null 2>"${work}/refused.err" || ! grep -q '^install refused: run as root' "${work}/refused.err"; then
  echo 'install ran without root' >&2
  exit 1
fi
# shellcheck disable=SC2086
{
  refused relative-stage scripts/install.sh --stage=stage --catalog="${catalog}" --tls-cert="${work}/tls/cert.pem" --tls-key="${work}/tls/key.pem"
  refused unknown-option scripts/install.sh ${base} --force
  refused other-name-certificate scripts/install.sh --stage="${stage}" --catalog="${catalog}" --tls-cert="${work}/other-tls/cert.pem" --tls-key="${work}/other-tls/key.pem"
  refused mismatched-key scripts/install.sh --stage="${stage}" --catalog="${catalog}" --tls-cert="${work}/tls/cert.pem" --tls-key="${work}/other-tls/key.pem"
  refused lan-without-networks scripts/install.sh ${base} --listen=192.0.2.10:8443
  refused all-interfaces scripts/install.sh ${base} --listen=0.0.0.0:8443 --allow-from=192.0.2.0/24
  refused injected-name scripts/install.sh ${base} --listen=192.0.2.10:8443 --allow-from=192.0.2.0/24 '--server-name=keybash.lan --tls-key=/tmp/x'
  refused tiny-cpu scripts/install.sh ${base} --cpu-percent=5
  refused word-in-limit scripts/install.sh ${base} '--tasks=512 --output=/etc'
  refused nobody-id scripts/install.sh ${base} --gateway-id=65534
  refused same-ids scripts/install.sh ${base} --gateway-id=65000 --worker-id=65000
  refused padded-id scripts/install.sh ${base} --gateway-id=065000
}
if test -z "${runtime}"; then
  refused rdp-catalog-without-runtime scripts/install.sh --stage="${stage}" --catalog="${work}/mixed.json" --tls-cert="${work}/tls/cert.pem" --tls-key="${work}/tls/key.pem"
fi
sudo -n groupadd --system keybash-worker
refused existing-account scripts/install.sh ${base}
sudo -n groupdel keybash-worker

install_ok scripts/install.sh
bootstrap="$(sed -n 's/^Bootstrap code (first account, valid 15 minutes): \([A-Za-z0-9_-]\{43\}\)$/\1/p' "${work}/install.out")"
test "${#bootstrap}" = 43
grep -Eq '^Instance key recovery code: KB1(-[A-Z2-7]{5}){11}-[A-Z2-7]{3}$' "${work}/install.out"
grep -q '^Keybash is installed and running at https://127.0.0.1:8443$' "${work}/install.out"
enabled='keybash-ssh-manager.service keybash-gateway.service'
test -z "${runtime}" || enabled="${enabled} keybash-rdp-manager.service"
for unit in ${enabled}; do
  systemctl is-active --quiet "${unit}"
  test "$(systemctl is-enabled "${unit}")" = enabled
done
# Verified HTTPS through the test authority, then the printed bootstrap code.
status="$(curl --silent --show-error --cacert "${work}/tls/ca.pem" -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/login)"
test "${status}" = 200
status="$(curl --silent --show-error --cacert "${work}/tls/ca.pem" -o /dev/null -w '%{http_code}' \
  -H 'Origin: https://127.0.0.1:8443' -H 'X-Keybash-Request: 1' -H 'Content-Type: application/json' \
  --data "{\"code\":\"${bootstrap}\",\"username\":\"installlab\",\"password\":\"Install lab synthetic passphrase 42!\"}" \
  https://127.0.0.1:8443/api/bootstrap)"
test "${status}" = 204
unset bootstrap
check_owner() {
  actual="$(sudo -n stat -c '%U:%G %a' "$1")"
  test "${actual}" = "$2" || { echo "$1 is ${actual}, expected $2" >&2; exit 1; }
}
check_owner /usr/local/libexec/keybash 'root:root 755'
check_owner /usr/local/libexec/keybash/keybash 'root:root 755'
check_owner /etc/keybash 'root:root 755'
check_owner /etc/keybash/targets.json 'root:root 644'
check_owner /etc/keybash/keys 'keybash-gateway:keybash-gateway 700'
check_owner /etc/keybash/keys/instance.key 'keybash-gateway:keybash-gateway 600'
check_owner /etc/keybash/tls 'keybash-gateway:keybash-gateway 700'
check_owner /etc/keybash/tls/key.pem 'keybash-gateway:keybash-gateway 600'
check_owner /var/lib/keybash 'keybash-gateway:keybash-gateway 700'
check_owner /var/lib/keybash/custody.db 'keybash-gateway:keybash-gateway 600'
check_owner /etc/systemd/system/keybash-gateway.service 'root:root 644'
echo 'Installed service runs, serves verified HTTPS and accepted the printed bootstrap code'

# --- Upgrade ------------------------------------------------------------------
# Stage B is stage A with an SSH worker that differs only in its build ID, so
# its digest is new and every unit that pins it must change.
sum_of() { sha256sum -- "$1" | cut -d ' ' -f 1; }
stage_b="${work}/stage-b"
cp -R "${stage}" "${stage_b}"
CGO_ENABLED=0 go build -trimpath -ldflags=-buildid=keybash-upgrade-lab -o "${stage_b}/bin/keybash-ssh-worker" ./cmd/keybash-ssh-worker
worker_a="$(sum_of "${stage}/bin/keybash-ssh-worker")"
worker_b="$(sum_of "${stage_b}/bin/keybash-ssh-worker")"
test "${worker_a}" != "${worker_b}"
snapshot() {
  sudo -n sha256sum /usr/local/libexec/keybash/* /etc/systemd/system/keybash.slice /etc/systemd/system/keybash-*.service \
    /etc/sysusers.d/keybash.conf /var/lib/keybash/custody.db
  if test -d /usr/local/lib/keybash; then sudo -n find /usr/local/lib/keybash -type f -exec sha256sum {} + | sort; fi
}
serves() { test "$(curl --silent --show-error --cacert "${work}/tls/ca.pem" -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/login)" = 200; }
signs_in() {
  status="$(curl --silent --show-error --cacert "${work}/tls/ca.pem" -o /dev/null -w '%{http_code}' \
    -H 'Origin: https://127.0.0.1:8443' -H 'X-Keybash-Request: 1' -H 'Content-Type: application/json' \
    --data '{"username":"installlab","password":"Install lab synthetic passphrase 42!"}' https://127.0.0.1:8443/api/session)"
  test "${status}" = 204
}
pinned() {
  grep -q -- "--worker-digest=$1 " /etc/systemd/system/keybash-gateway.service &&
    grep -q -- "--worker-sha256=$1 " /etc/systemd/system/keybash-ssh-manager.service &&
    test "$(sum_of /usr/local/libexec/keybash/keybash-ssh-worker)" = "$1"
}
# refused_upgrade LABEL UPGRADER ARGS...: refused first, and the host, the lock
# and the running service are exactly as before.
refused_upgrade() {
  label="$1" upgrader="$2"
  shift 2
  before="$(snapshot)"
  if sudo -n sh "${upgrader}" "$@" >"${work}/upgrade.out" 2>"${work}/upgrade.err"; then
    echo "upgrade accepted: ${label}" >&2
    return 1
  fi
  if ! grep -q '^upgrade refused: ' "${work}/upgrade.err" || test "$(snapshot)" != "${before}" || test -e /run/keybash-upgrade.lock ||
    ! systemctl is-active --quiet keybash-gateway.service; then
    echo "upgrade did not refuse before changing the host: ${label}" >&2
    return 1
  fi
  echo "Upgrade refused before any change: ${label} ($(cut -c1-80 "${work}/upgrade.err"))"
}
# A backup is named by the second, so two upgrades never share one.
upgrade_ok() {
  sleep 1
  if ! sudo -n sh "$1" --stage="$2" >"${work}/upgrade.out" 2>"${work}/upgrade.err"; then
    cat "${work}/upgrade.err" >&2
    sudo -n journalctl --no-pager -n 60 -u keybash-gateway.service -u keybash-ssh-manager.service -u keybash-rdp-manager.service >&2 || true
    return 1
  fi
  grep -q '^Keybash is upgraded and running' "${work}/upgrade.out"
}
signs_in

if sh scripts/upgrade.sh --stage="${stage_b}" >/dev/null 2>"${work}/upgrade.err" || ! grep -q '^upgrade refused: run as root' "${work}/upgrade.err"; then
  echo 'upgrade ran without root' >&2
  exit 1
fi
stage_lacking="${work}/stage-lacking"
cp -R "${stage_b}" "${stage_lacking}"
rm -f -- "${stage_lacking}/bin/keybash-service-check"
stage_mode="${work}/stage-mode"
cp -R "${stage_b}" "${stage_mode}"
if test -n "${runtime}"; then rm -rf -- "${stage_mode}/runtime"; else mkdir "${stage_mode}/runtime"; fi
refused_upgrade unknown-option scripts/upgrade.sh --stage="${stage_b}" --force
refused_upgrade relative-stage scripts/upgrade.sh --stage=stage-b
refused_upgrade stage-lacks-program scripts/upgrade.sh --stage="${stage_lacking}"
refused_upgrade other-mode scripts/upgrade.sh --stage="${stage_mode}"
sudo -n mkdir /run/keybash-upgrade.lock
before="$(snapshot)"
if sudo -n sh scripts/upgrade.sh --stage="${stage_b}" >/dev/null 2>"${work}/upgrade.err" ||
  ! grep -q '^upgrade refused: another upgrade is running' "${work}/upgrade.err" || test "$(snapshot)" != "${before}"; then
  echo 'upgrade ran beside another upgrade' >&2
  exit 1
fi
sudo -n rmdir /run/keybash-upgrade.lock
# A unit edited by hand is refused: its settings could not be read back.
sudo -n cp -p /etc/systemd/system/keybash-gateway.service "${work}/gateway.unit"
edit_unit() { printf '%s\n' '# edited by hand' | sudo -n tee -a /etc/systemd/system/keybash-gateway.service >/dev/null; }
edit_unit
refused_upgrade edited-unit scripts/upgrade.sh --stage="${stage_b}"
sudo -n cp -p "${work}/gateway.unit" /etc/systemd/system/keybash-gateway.service

upgrade_ok scripts/upgrade.sh "${stage_b}"
pinned "${worker_b}" || { echo 'the upgrade did not pin the new worker everywhere' >&2; exit 1; }
for unit in ${enabled}; do
  systemctl is-active --quiet "${unit}"
  test "$(systemctl is-enabled "${unit}")" = enabled
done
serves
signs_in || { echo 'the account made before the upgrade no longer signs in' >&2; exit 1; }
backup="$(sudo -n find /var/backups/keybash -mindepth 1 -maxdepth 1 -type d)"
test "$(printf '%s\n' "${backup}" | wc -l)" = 1
test "$(sudo -n sha256sum "${backup}/bin/keybash-ssh-worker" | cut -d ' ' -f 1)" = "${worker_a}"
check_owner /var/backups/keybash 'root:root 700'
check_owner "${backup}" 'root:root 700'
check_owner "${backup}/custody.db" 'keybash-gateway:keybash-gateway 600'
test ! -e /run/keybash-upgrade.lock
echo 'Upgrade pinned the new worker, kept the account and left a root-only backup'

# Stage C passes every check but its gateway never serves: the upgrade must put
# the previous programs, units and database back and start them.
stage_c="${work}/stage-c"
cp -R "${stage_b}" "${stage_c}"
mv "${stage_c}/bin/keybash" "${stage_c}/bin/keybash-real"
printf '#!/bin/sh\ncase "$1" in check-*) exec %s "$@" ;; esac\nexit 1\n' "${stage_c}/bin/keybash-real" > "${stage_c}/bin/keybash"
chmod 755 "${stage_c}/bin/keybash"
broken_upgrade() {
  sleep 1
  before="$(snapshot)"
  if sudo -n sh "$1" --stage="${stage_c}" >"${work}/upgrade.out" 2>"${work}/upgrade.err"; then return 1; fi
  grep -q '^upgrade failed: ' "${work}/upgrade.err" && grep -q '^The previous version is back and running' "${work}/upgrade.err" &&
    test "$(snapshot)" = "${before}" && serves && signs_in
}
broken_upgrade scripts/upgrade.sh || { echo 'a failed upgrade did not put the previous version back' >&2; cat "${work}/upgrade.err" >&2; exit 1; }
echo 'A failed upgrade put the previous programs, units and database back and started them'

# Mutations on a copy of the upgrader, never the repository file. Each must
# make the check it targets fail; a real upgrade then leaves the host working.
fresh_upgrader() { cp scripts/upgrade.sh "${work}/upgrader.sh"; }
mutate_upgrader() {
  test "$(grep -cF -- "$1" "${work}/upgrader.sh")" = 1 || { echo "upgrader mutation anchor missing: $1" >&2; exit 1; }
  awk -v old="$1" -v new="$2" '{ i = index($0, old); if (i) $0 = substr($0, 1, i - 1) new substr($0, i + length(old)); print }' \
    "${work}/upgrader.sh" > "${work}/upgrader.next"
  mv "${work}/upgrader.next" "${work}/upgrader.sh"
}
escaped_upgrade() { echo "upgrader mutation escaped: $1" >&2; exit 1; }
# Refusing direction: without the plan check, an edited unit is upgraded over.
fresh_upgrader
mutate_upgrader 'cmp -s "${work}/installed/${unit}" "${systemd}/${unit}" ||' 'true ||'
edit_unit
if refused_upgrade edited-unit "${work}/upgrader.sh" --stage="${stage_b}" >/dev/null 2>&1; then escaped_upgrade skip-unit-check; fi
# Restoring direction: without restore, a failed upgrade leaves the host down.
fresh_upgrader
mutate_upgrader 'elif restore; then' 'elif true; then'
if broken_upgrade "${work}/upgrader.sh" >/dev/null 2>&1; then escaped_upgrade skip-restore; fi
# The mutant left the swapped-out runtime behind, which the upgrader refuses.
sudo -n rm -rf -- /usr/local/lib/keybash/rdp.old
upgrade_ok scripts/upgrade.sh "${stage_b}"
pinned "${worker_b}"
# Accepting direction: a valid upgrade must pin the worker it installs.
fresh_upgrader
mutate_upgrader '--worker-digest="${new_worker}" ${new_rdp}' '--worker-digest="${old_worker}" ${new_rdp}'
if upgrade_ok "${work}/upgrader.sh" "${stage}" 2>/dev/null && pinned "${worker_a}"; then escaped_upgrade pin-installed-worker; fi
upgrade_ok scripts/upgrade.sh "${stage}"
pinned "${worker_a}"
serves
echo 'Upgrader mutations in both directions failed their intended checks; the host runs stage A again'

# Over an existing install, refusal must come first and change nothing.
before="$(sudo -n sha256sum /etc/systemd/system/keybash-*.service /etc/keybash/targets.json /var/lib/keybash/custody.db)"
if sudo -n sh scripts/install.sh ${base} >/dev/null 2>"${work}/again.err" || ! grep -q '^install refused: .* already exists' "${work}/again.err"; then
  echo 'second install was not refused first' >&2
  exit 1
fi
test "$(sudo -n sha256sum /etc/systemd/system/keybash-*.service /etc/keybash/targets.json /var/lib/keybash/custody.db)" = "${before}"
systemctl is-active --quiet keybash-gateway.service

sudo -n sh scripts/uninstall.sh >/dev/null
for unit in ${enabled}; do
  if systemctl is-active --quiet "${unit}"; then echo "${unit} still runs" >&2; exit 1; fi
  test ! -e "/etc/systemd/system/${unit}"
done
test ! -e /usr/local/libexec/keybash
sudo -n test -f /var/lib/keybash/custody.db
sudo -n test -f /etc/keybash/keys/instance.key
if sudo -n sh scripts/install.sh ${base} >/dev/null 2>&1; then echo 'install reused leftover data' >&2; exit 1; fi
echo 'Uninstall removed programs and units and kept the data'
reset_host

# Mutations on a copy of the installer, never the repository file. Each must
# make the check above that it targets fail; the host is reset after each.
fresh_mutant() { cp scripts/install.sh "${work}/mutant.sh"; }
mutate() {
  test "$(grep -cF -- "$1" "${work}/mutant.sh")" = 1 || { echo "mutation anchor missing: $1" >&2; exit 1; }
  awk -v old="$1" -v new="$2" '{ i = index($0, old); if (i) $0 = substr($0, 1, i - 1) new substr($0, i + length(old)); print }' \
    "${work}/mutant.sh" > "${work}/mutant.next"
  mv "${work}/mutant.next" "${work}/mutant.sh"
}
escaped() { echo "installer mutation escaped: $1" >&2; exit 1; }

# Refusing direction: a wrong certificate must stop the install first.
fresh_mutant
mutate '"${stage}/bin/keybash" check-tls ' 'true '
if refused other-name-certificate "${work}/mutant.sh" --stage="${stage}" --catalog="${catalog}" --tls-cert="${work}/other-tls/cert.pem" --tls-key="${work}/other-tls/key.pem" >/dev/null 2>&1; then
  escaped skip-tls-check
fi
reset_host
if test -z "${runtime}"; then
  fresh_mutant
  mutate '--config="${work}/targets.json" --ssh-only' '--config="${work}/targets.json"'
  if refused rdp-catalog "${work}/mutant.sh" --stage="${stage}" --catalog="${work}/mixed.json" --tls-cert="${work}/tls/cert.pem" --tls-key="${work}/tls/key.pem" >/dev/null 2>&1; then
    escaped skip-ssh-only
  fi
  reset_host
fi
# Without every fresh-host check, a second install no longer refuses first.
fresh_mutant
mutate 'test ! -e "${path}" && test ! -L "${path}" ||' 'true ||'
mutate 'test ! -e "/etc/systemd/system/${unit}" ||' 'true ||'
mutate 'if printf' 'if false && printf'
mutate 'if getent passwd "${account}" >/dev/null || getent group "${account}" >/dev/null; then' 'if false; then'
install_ok scripts/install.sh
if ! sudo -n sh "${work}/mutant.sh" ${base} >/dev/null 2>"${work}/again.err" && grep -q '^install refused: .* already exists' "${work}/again.err"; then
  escaped skip-fresh-checks
fi
reset_host
# Accepting direction: a valid install must succeed.
fresh_mutant
mutate 'getent group "$1" >/dev/null && return 1' 'return 1'
if install_ok "${work}/mutant.sh" 2>/dev/null; then escaped no-free-id; fi
reset_host
echo 'Installer mutations in both directions failed their intended checks'
