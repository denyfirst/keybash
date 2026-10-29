#!/bin/sh
# Installs Keybash from a stage made by scripts/build-stage.sh onto a fresh
# Linux x86-64 host with systemd and cgroup v2. Run as root.
#
# It never replaces an existing file, unit or account: every check, including
# the catalog, the TLS pair and the service plan, runs before the first change.
# The bootstrap code and the instance key's recovery code go to this terminal
# only. See docs/INSTALL.md and docs/INSTALL-AZ.md.
set -eu
umask 022
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

refuse() { printf 'install refused: %s\n' "$1" >&2; exit 1; }

stage='' catalog='' cert='' key='' listen=127.0.0.1:8443 allow='' name=''
cpu=200 memory=1024 tasks=512 gateway_id='' worker_id=''
for argument in "$@"; do
  case "${argument}" in
    --stage=*) stage="${argument#*=}" ;;
    --catalog=*) catalog="${argument#*=}" ;;
    --tls-cert=*) cert="${argument#*=}" ;;
    --tls-key=*) key="${argument#*=}" ;;
    --listen=*) listen="${argument#*=}" ;;
    --allow-from=*) allow="${argument#*=}" ;;
    --server-name=*) name="${argument#*=}" ;;
    --cpu-percent=*) cpu="${argument#*=}" ;;
    --memory-mib=*) memory="${argument#*=}" ;;
    --tasks=*) tasks="${argument#*=}" ;;
    --gateway-id=*) gateway_id="${argument#*=}" ;;
    --worker-id=*) worker_id="${argument#*=}" ;;
    *) refuse "unknown option ${argument} (options take the --name=value form)" ;;
  esac
done

libexec=/usr/local/libexec/keybash
runtime=/usr/local/lib/keybash/rdp
units='keybash.slice keybash-gateway.service keybash-ssh-manager.service keybash-rdp-manager.service'

# --- Host -------------------------------------------------------------------
test "$(id -u)" = 0 || refuse 'run as root'
test "$(uname -sm)" = 'Linux x86_64' || refuse 'Linux x86-64 only'
test "$(cat /proc/1/comm)" = systemd || refuse 'systemd must be PID 1'
test -f /sys/fs/cgroup/cgroup.controllers || refuse 'cgroup v2 is required'
for tool in systemctl systemd-sysusers systemd-analyze getent sha256sum install find setpriv prlimit ss; do
  command -v "${tool}" >/dev/null 2>&1 || refuse "missing ${tool}"
done
test -x /usr/bin/bwrap || refuse 'missing /usr/bin/bwrap (apt-get install bubblewrap)'
test -x /usr/bin/setpriv || refuse 'missing /usr/bin/setpriv'

# --- Stage ------------------------------------------------------------------
case "${stage}" in /*) ;; *) refuse '--stage must be an absolute path' ;; esac
test -d "${stage}/bin" && test ! -L "${stage}" && test ! -L "${stage}/bin" || refuse 'stage has no bin directory'
programs='keybash keybash-ssh-manager keybash-ssh-worker keybash-service-check keybash-service-plan'
rdp=no
if test -e "${stage}/runtime"; then
  rdp=yes
  programs="${programs} keybash-rdp-manager keybash-rdp-worker keybash-rdp-inventory"
  test -d "${stage}/runtime" && test ! -L "${stage}/runtime" || refuse 'stage runtime is not a directory'
  test -z "$(find "${stage}/runtime" -type l -print -quit)" || refuse 'stage runtime contains a symlink'
  test -z "$(find "${stage}/runtime" -type f -links +1 -print -quit)" || refuse 'stage runtime contains a hard link'
fi
for program in ${programs}; do
  test -f "${stage}/bin/${program}" && test ! -L "${stage}/bin/${program}" && test -x "${stage}/bin/${program}" ||
    refuse "stage lacks ${program}"
done

# --- Fresh host: nothing of Keybash may exist ---------------------------------
for path in "${libexec}" /usr/local/lib/keybash /etc/keybash /var/lib/keybash /etc/sysusers.d/keybash.conf \
  /run/keybash-manager /run/keybash-rdp-manager /run/systemd/system.control/keybash.slice.d; do
  test ! -e "${path}" && test ! -L "${path}" || refuse "${path} already exists (this installer only installs fresh)"
done
inventory="$(systemctl list-unit-files --all --no-legend --no-pager; systemctl list-units --all --no-legend --no-pager --plain)" ||
  refuse 'cannot list systemd units'
for unit in ${units}; do
  test ! -e "/etc/systemd/system/${unit}" || refuse "/etc/systemd/system/${unit} already exists"
  if printf '%s\n' "${inventory}" | tr -s ' \t' '\n\n' | grep -qx "${unit}"; then refuse "${unit} is already known to systemd"; fi
done
for account in keybash-gateway keybash-worker; do
  if getent passwd "${account}" >/dev/null || getent group "${account}" >/dev/null; then refuse "account ${account} already exists"; fi
done

# --- Identities: given, or the first free pair below 65534 -------------------
free_id() {
  getent passwd "$1" >/dev/null && return 1
  getent group "$1" >/dev/null && return 1
  return 0
}
pick_id() {
  candidate=65533
  while test "${candidate}" -ge 60000; do
    if test "${candidate}" != "$1" && free_id "${candidate}"; then printf '%s\n' "${candidate}"; return 0; fi
    candidate=$((candidate - 1))
  done
  return 1
}
for value in "${gateway_id}" "${worker_id}"; do
  case "${value}" in '') ;; *[!0-9]* | 0*) refuse 'IDs are positive integers' ;; esac
done
# Limits are checked again by the service plan; here they must be plain numbers.
for value in "${cpu}" "${memory}" "${tasks}"; do
  case "${value}" in '' | *[!0-9]* | 0*) refuse 'limits are positive integers' ;; esac
  test "${#value}" -le 9 || refuse 'limit out of range'
done
test -n "${gateway_id}" || gateway_id="$(pick_id none)" || refuse 'no free gateway ID'
test -n "${worker_id}" || worker_id="$(pick_id "${gateway_id}")" || refuse 'no free worker ID'
test "${gateway_id}" != "${worker_id}" || refuse 'gateway and worker IDs must differ'
for id in "${gateway_id}" "${worker_id}"; do
  test "${#id}" -le 10 && test "${id}" -le 2147483647 && test "${id}" != 65534 || refuse "ID ${id} is out of range"
  free_id "${id}" || refuse "ID ${id} is already in use"
done

# --- Configuration, checked with the staged programs -------------------------
work="$(mktemp -d /run/keybash-install.XXXXXX)"
changed=no
finish() {
  status=$?
  rm -rf -- "${work}"
  if test "${status}" != 0 && test "${changed}" = yes; then
    printf '%s\n' 'Install stopped after it had changed this host; nothing was rolled back.' \
      'Inspect: systemctl status keybash-gateway; journalctl -u keybash-gateway -u keybash-ssh-manager' \
      'Program files and units can be removed with scripts/uninstall.sh; data stays.' >&2
  fi
  exit "${status}"
}
trap finish EXIT
chmod 0700 "${work}"
# The catalog loader requires a root-owned file in root-owned directories.
for file in "${catalog}" "${cert}" "${key}"; do
  case "${file}" in /*) ;; *) refuse '--catalog, --tls-cert and --tls-key must be absolute paths' ;; esac
  test -f "${file}" && test ! -L "${file}" || refuse "${file} is not a regular file"
done
install -o root -g root -m 0644 "${catalog}" "${work}/targets.json"
if test "${rdp}" = yes; then
  "${stage}/bin/keybash" check-targets --config="${work}/targets.json" >/dev/null || refuse 'catalog refused (keybash check-targets)'
else
  "${stage}/bin/keybash" check-targets --config="${work}/targets.json" --ssh-only >/dev/null ||
    refuse 'catalog refused: it must be valid and, without an RDP runtime in the stage, SSH only'
fi
set -- --listen="${listen}"
test -z "${allow}" || set -- "$@" --allow-from="${allow}"
test -z "${name}" || set -- "$@" --server-name="${name}"
"${stage}/bin/keybash" check-tls --tls-cert="${cert}" --tls-key="${key}" "$@" >/dev/null ||
  refuse 'TLS pair refused: it must load, be valid now and cover the address or --server-name browsers use'
digest() { sha256sum -- "$1" | cut -d ' ' -f 1; }
ssh_digest="$(digest "${stage}/bin/keybash-ssh-worker")"
plan_args="--gateway-uid=${gateway_id} --gateway-gid=${gateway_id} --worker-uid=${worker_id} --worker-gid=${worker_id} --worker-digest=${ssh_digest} --cpu-percent=${cpu} --memory-mib=${memory} --tasks=${tasks}"
# shellcheck disable=SC2086 # plan_args holds only the integers and digest above
"${stage}/bin/keybash-service-plan" ${plan_args} "$@" --output="${work}/preview" >/dev/null ||
  refuse 'service plan refused (listener, networks, server name or limits)'

# --- Install: the first change -------------------------------------------------
changed=yes
mkdir -m 0755 -p /usr/local/libexec
mkdir -m 0755 "${libexec}"
for program in ${programs}; do
  install -o root -g root -m 0755 "${stage}/bin/${program}" "${libexec}/${program}"
  test "$(digest "${libexec}/${program}")" = "$(digest "${stage}/bin/${program}")" || refuse "${program} changed while installing"
done
test "$(digest "${libexec}/keybash-ssh-worker")" = "${ssh_digest}" || refuse 'SSH worker changed while installing'
if test "${rdp}" = yes; then
  mkdir -m 0755 -p /usr/local/lib/keybash
  cp -R -- "${stage}/runtime" "${runtime}"
  chown -R root:root "${runtime}"
  chmod -R go-w "${runtime}"
  test -z "$(find "${runtime}" -type l -print -quit)" || refuse 'installed runtime contains a symlink'
  test -z "$(find "${runtime}" -type f -links +1 -print -quit)" || refuse 'installed runtime contains a hard link'
  rdp_digest="$(digest "${libexec}/keybash-rdp-worker")"
  runtime_digest="$("${libexec}/keybash-rdp-inventory" "${runtime}")" || refuse 'installed RDP runtime refused'
  set -- "$@" --rdp-worker-digest="${rdp_digest}" --rdp-runtime-digest="${runtime_digest}"
fi
# shellcheck disable=SC2086
"${libexec}/keybash-service-plan" ${plan_args} "$@" --output="${work}/plan" >/dev/null || refuse 'service plan refused'
install -o root -g root -m 0644 "${work}/plan/keybash.conf" /etc/sysusers.d/keybash.conf
for unit in ${units}; do
  if test -f "${work}/plan/${unit}"; then install -o root -g root -m 0644 "${work}/plan/${unit}" "/etc/systemd/system/${unit}"; fi
done
systemd-sysusers /etc/sysusers.d/keybash.conf
for account in keybash-gateway:"${gateway_id}" keybash-worker:"${worker_id}"; do
  test "$(id -u "${account%%:*}")" = "${account#*:}" && test "$(id -g "${account%%:*}")" = "${account#*:}" ||
    refuse "${account%%:*} was not created with ID ${account#*:}"
done

install -d -o root -g root -m 0755 /etc/keybash
install -d -o keybash-gateway -g keybash-gateway -m 0700 /etc/keybash/keys /etc/keybash/tls /var/lib/keybash
install -o root -g root -m 0644 "${work}/targets.json" /etc/keybash/targets.json
install -o keybash-gateway -g keybash-gateway -m 0600 "${cert}" /etc/keybash/tls/cert.pem
install -o keybash-gateway -g keybash-gateway -m 0600 "${key}" /etc/keybash/tls/key.pem

as_gateway() {
  setpriv --reuid=keybash-gateway --regid=keybash-gateway --clear-groups --reset-env -- "$@"
}
bootstrap="$(as_gateway "${libexec}/keybash" init --data=/var/lib/keybash --key-file=/etc/keybash/keys/instance.key)" ||
  refuse 'database initialization failed'
recovery="$(as_gateway "${libexec}/keybash" key-export --data=/var/lib/keybash --key-file=/etc/keybash/keys/instance.key)" ||
  refuse 'instance key recovery code failed'

enabled='keybash-ssh-manager.service'
test "${rdp}" = no || enabled="${enabled} keybash-rdp-manager.service"
enabled="${enabled} keybash-gateway.service"
# shellcheck disable=SC2086
systemd-analyze verify /etc/systemd/system/keybash.slice $(printf '/etc/systemd/system/%s ' ${enabled})
systemctl daemon-reload
# shellcheck disable=SC2086
systemctl enable --now ${enabled}
attempt=0
until systemctl is-active --quiet keybash-gateway.service && ss -Hltn "sport = :${listen##*:}" | grep -q .; do
  attempt=$((attempt + 1))
  test "${attempt}" -lt 20 || refuse 'the gateway did not start listening'
  sleep 0.5
done
# shellcheck disable=SC2086
for unit in ${enabled}; do systemctl is-active --quiet "${unit}" || refuse "${unit} is not running"; done

origin="https://${name:-${listen%:*}}:${listen##*:}"
printf '%s\n' "Keybash is installed and running at ${origin}" \
  "Mode: $(test "${rdp}" = yes && echo 'SSH and RDP' || echo 'SSH only'); gateway ID ${gateway_id}, worker ID ${worker_id}." \
  '' \
  '--- Shown once. Do not paste into chat, logs, tickets or screenshots. ---' \
  "Bootstrap code (first account, valid 15 minutes): ${bootstrap}" \
  "Instance key recovery code: ${recovery}" \
  '  Write it down apart from this server and from any backup. Without it no' \
  '  backup can be restored; with a backup, it opens everything.' \
  '---' \
  "Open ${origin}/login and create the first account with the bootstrap code." \
  'If it expired: systemctl stop keybash-gateway; then as keybash-gateway run' \
  '  keybash bootstrap-renew --data=/var/lib/keybash --key-file=/etc/keybash/keys/instance.key' \
  '  and start the service again.'
