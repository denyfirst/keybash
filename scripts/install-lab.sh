#!/bin/sh
# CI only, on a disposable runner: builds a stage, checks that the installer
# refuses bad input before changing anything, installs, checks the running
# service end to end, refuses a second install, uninstalls (keeping data), and
# runs installer mutations in both directions. Removes everything it made.
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
  sudo -n rm -rf -- /var/lib/keybash /etc/keybash
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
