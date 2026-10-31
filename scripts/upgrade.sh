#!/bin/sh
# Upgrades an installed Keybash to the programs of a stage made by
# scripts/build-stage.sh. Run as root:  upgrade.sh --stage=/abs/stage
#
# It keeps everything install.sh chose. The IDs, limits, listener, networks
# and server name are read back from the installed gateway unit and accepted
# only if the installed service plan, given them, writes every installed unit
# again byte for byte, so a unit edited by hand is refused. The catalog, TLS
# pair, keys and data stay where they are. Every check runs before the first
# change: the new programs must accept this host's catalog and TLS pair and
# write a plan from the same settings with the new workers' digests.
#
# Before anything is replaced, the old programs, units, RDP runtime and
# database are copied to /var/backups/keybash/<time>. If the new version does
# not come up, they are put back and the old version is started again.
# Upgrading stops the service, so open sessions end. See docs/INSTALL.md.
set -eu
umask 022
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

refuse() { printf 'upgrade refused: %s\n' "$1" >&2; exit 1; }
fail() { printf 'upgrade failed: %s\n' "$1" >&2; exit 1; }

stage=''
for argument in "$@"; do
  case "${argument}" in
    --stage=*) stage="${argument#*=}" ;;
    *) refuse "unknown option ${argument} (options take the --name=value form)" ;;
  esac
done

libexec=/usr/local/libexec/keybash
runtime=/usr/local/lib/keybash/rdp
systemd=/etc/systemd/system
database=/var/lib/keybash/custody.db
backups=/var/backups/keybash

# --- Host -------------------------------------------------------------------
test "$(id -u)" = 0 || refuse 'run as root'
test "$(uname -sm)" = 'Linux x86_64' || refuse 'Linux x86-64 only'
test "$(cat /proc/1/comm)" = systemd || refuse 'systemd must be PID 1'
for tool in systemctl systemd-analyze sha256sum install find ss cmp date; do
  command -v "${tool}" >/dev/null 2>&1 || refuse "missing ${tool}"
done

# --- The installed Keybash ----------------------------------------------------
test -d "${libexec}" && test ! -L "${libexec}" || refuse 'Keybash is not installed here (install.sh installs it)'
rdp=no
if test -e "${systemd}/keybash-rdp-manager.service" || test -L "${systemd}/keybash-rdp-manager.service"; then rdp=yes; fi
programs='keybash keybash-ssh-manager keybash-ssh-worker keybash-service-check keybash-service-plan'
units='keybash.slice keybash-gateway.service keybash-ssh-manager.service'
enabled='keybash-ssh-manager.service'
if test "${rdp}" = yes; then
  programs="${programs} keybash-rdp-manager keybash-rdp-worker keybash-rdp-inventory"
  units="${units} keybash-rdp-manager.service"
  enabled="${enabled} keybash-rdp-manager.service"
  test -d "${runtime}" && test ! -L "${runtime}" || refuse "${runtime} is missing"
  for path in "${runtime}.new" "${runtime}.old"; do
    test ! -e "${path}" && test ! -L "${path}" || refuse "${path} exists (left by an earlier upgrade?)"
  done
fi
enabled="${enabled} keybash-gateway.service"
for program in ${programs}; do
  test -f "${libexec}/${program}" && test ! -L "${libexec}/${program}" || refuse "${libexec}/${program} is missing"
done
for unit in ${units}; do
  test -f "${systemd}/${unit}" && test ! -L "${systemd}/${unit}" || refuse "${systemd}/${unit} is missing"
done
for file in /etc/sysusers.d/keybash.conf /etc/keybash/targets.json /etc/keybash/tls/cert.pem /etc/keybash/tls/key.pem \
  /etc/keybash/keys/instance.key "${database}"; do
  test -f "${file}" && test ! -L "${file}" || refuse "${file} is missing"
done

# --- Stage ------------------------------------------------------------------
case "${stage}" in /*) ;; *) refuse '--stage must be an absolute path' ;; esac
test -d "${stage}/bin" && test ! -L "${stage}" && test ! -L "${stage}/bin" || refuse 'stage has no bin directory'
staged_rdp=no
if test -e "${stage}/runtime" || test -L "${stage}/runtime"; then staged_rdp=yes; fi
test "${staged_rdp}" = "${rdp}" || refuse 'the stage and this installation differ in RDP; an upgrade keeps the mode (reinstall to change it)'
if test "${rdp}" = yes; then
  test -d "${stage}/runtime" && test ! -L "${stage}/runtime" || refuse 'stage runtime is not a directory'
  test -z "$(find "${stage}/runtime" -type l -print -quit)" || refuse 'stage runtime contains a symlink'
  test -z "$(find "${stage}/runtime" -type f -links +1 -print -quit)" || refuse 'stage runtime contains a hard link'
fi
for program in ${programs}; do
  test -f "${stage}/bin/${program}" && test ! -L "${stage}/bin/${program}" && test -x "${stage}/bin/${program}" ||
    refuse "stage lacks ${program}"
done

# --- The settings install.sh chose -------------------------------------------
# The plan wrote them into the gateway unit: integers and digests on the start
# check's line, the listener and its exposure on the start line. Each word must
# be one of the plan's own; the plan check below proves they are exactly its.
set -f
pre="$(sed -n 's|^ExecStartPre=/usr/local/libexec/keybash/keybash-service-check --role=gateway ||p' "${systemd}/keybash-gateway.service")"
start="$(sed -n 's|^ExecStart=/usr/local/libexec/keybash/keybash serve-[a-z]*-lab ||p' "${systemd}/keybash-gateway.service")"
test -n "${pre}" && test -n "${start}" && test "$(printf '%s\n' "${pre}" | wc -l)" = 1 && test "$(printf '%s\n' "${start}" | wc -l)" = 1 ||
  refuse 'the gateway unit is not one install.sh wrote'
kept='' exposure='' listen='' old_worker='' old_rdp_worker='' old_runtime=''
for word in ${pre}; do
  case "${word}" in
    --worker-digest=*) old_worker="${word#*=}" ;;
    --rdp-worker-digest=*) old_rdp_worker="${word#*=}" ;;
    --rdp-runtime-digest=*) old_runtime="${word#*=}" ;;
    --gateway-uid=* | --gateway-gid=* | --worker-uid=* | --worker-gid=* | --cpu-percent=* | --memory-mib=* | --tasks=*)
      case "${word#*=}" in '' | *[!0-9]*) refuse "unexpected setting in the gateway unit: ${word}" ;; esac
      kept="${kept} ${word}"
      ;;
    *) refuse "unexpected setting in the gateway unit: ${word}" ;;
  esac
done
for word in ${start}; do
  case "${word}" in
    --listen=* | --allow-from=* | --server-name=*)
      printf '%s\n' "${word#*=}" | grep -Eqx '[][A-Za-z0-9.:,/_-]{1,255}' || refuse "unexpected setting in the gateway unit: ${word}"
      case "${word}" in --listen=*) listen="${word#*=}" ;; *) exposure="${exposure} ${word}" ;; esac
      ;;
    --data=/var/lib/keybash | --key-file=/etc/keybash/keys/instance.key | --tls-cert=/etc/keybash/tls/cert.pem | \
      --tls-key=/etc/keybash/tls/key.pem | --config=/etc/keybash/targets.json | \
      --ssh-manager=/run/keybash-manager/control.sock | --rdp-manager=/run/keybash-rdp-manager/control.sock) ;;
    *) refuse "unexpected setting in the gateway unit: ${word}" ;;
  esac
done
test -n "${listen}" && test -n "${old_worker}" || refuse 'the gateway unit is not one install.sh wrote'
old_rdp=''
if test "${rdp}" = yes; then
  test -n "${old_rdp_worker}" && test -n "${old_runtime}" || refuse 'the gateway unit is not one install.sh wrote'
  old_rdp="--rdp-worker-digest=${old_rdp_worker} --rdp-runtime-digest=${old_runtime}"
else
  test -z "${old_rdp_worker}${old_runtime}" || refuse 'the gateway unit names an RDP runtime this host lacks'
fi

# --- Checks with the installed and the new programs -----------------------------
mkdir -m 0700 /run/keybash-upgrade.lock 2>/dev/null ||
  refuse 'another upgrade is running (or one was killed: remove /run/keybash-upgrade.lock)'
work='' changed=no stopped=no swapped=no started=no backup=''
digest() { sha256sum -- "$1" | cut -d ' ' -f 1; }
ready() {
  attempt=0
  until systemctl is-active --quiet keybash-gateway.service && ss -Hltn "sport = :${listen##*:}" | grep -q .; do
    attempt=$((attempt + 1))
    test "${attempt}" -lt 20 || return 1
    sleep 0.5
  done
  # shellcheck disable=SC2086 # enabled holds fixed unit names
  for unit in ${enabled}; do systemctl is-active --quiet "${unit}" || return 1; done
}
# Puts back what the backup holds and starts it. Each step is checked here,
# since a failing command in a condition does not stop the script.
restore() {
  # shellcheck disable=SC2086
  systemctl stop ${enabled} 2>/dev/null
  for program in ${programs}; do
    install -o root -g root -m 0755 "${backup}/bin/${program}" "${libexec}/${program}.new" &&
      mv -f -- "${libexec}/${program}.new" "${libexec}/${program}" || return 1
  done
  for unit in ${units}; do
    install -o root -g root -m 0644 "${backup}/units/${unit}" "${systemd}/${unit}" || return 1
  done
  if test "${rdp}" = yes && test -d "${runtime}.old"; then
    rm -rf -- "${runtime}" && mv -- "${runtime}.old" "${runtime}" || return 1
  fi
  # Only a new version that ran can have written to the database.
  if test "${started}" = yes; then
    cp -p -- "${backup}/custody.db" "${database}" || return 1
  fi
  systemctl daemon-reload || return 1
  # shellcheck disable=SC2086
  systemctl start ${enabled} || return 1
  ready
}
finish() {
  status=$?
  trap - EXIT
  set +e
  if test "${status}" != 0 && test "${changed}" = yes; then
    if test "${swapped}" = no && test "${stopped}" = no; then
      printf '%s\n' 'Nothing was replaced; the running version is unchanged.' >&2
    elif restore; then
      printf '%s\n' "The previous version is back and running. Its copies stay in ${backup}." >&2
    else
      printf '%s\n' 'The previous version could not be put back.' \
        "Its programs, units, runtime and database are in ${backup}; restore them by hand, then" \
        '  systemctl daemon-reload; systemctl start keybash-gateway' \
        'Inspect: journalctl -u keybash-gateway -u keybash-ssh-manager' >&2
    fi
  fi
  test -z "${work}" || rm -rf -- "${work}"
  if test "${rdp}" = yes; then rm -rf -- "${runtime}.new"; fi
  rmdir /run/keybash-upgrade.lock
  exit "${status}"
}
trap finish EXIT
work="$(mktemp -d /run/keybash-upgrade.XXXXXX)"
chmod 0700 "${work}"

# shellcheck disable=SC2086 # kept, exposure and old_rdp hold only the words checked above
"${libexec}/keybash-service-plan" ${kept} --worker-digest="${old_worker}" ${old_rdp} --listen="${listen}" ${exposure} \
  --output="${work}/installed" >/dev/null || refuse 'the installed service plan refused the settings read back from the gateway unit'
for unit in ${units}; do
  cmp -s "${work}/installed/${unit}" "${systemd}/${unit}" ||
    refuse "${systemd}/${unit} is not what this installation's plan writes (edited by hand?)"
done
cmp -s "${work}/installed/keybash.conf" /etc/sysusers.d/keybash.conf ||
  refuse '/etc/sysusers.d/keybash.conf is not what this installation'"'"'s plan writes'

if test "${rdp}" = yes; then
  "${stage}/bin/keybash" check-targets --config=/etc/keybash/targets.json >/dev/null || refuse 'catalog refused by the new version (keybash check-targets)'
else
  "${stage}/bin/keybash" check-targets --config=/etc/keybash/targets.json --ssh-only >/dev/null ||
    refuse 'catalog refused by the new version (keybash check-targets --ssh-only)'
fi
# shellcheck disable=SC2086
"${stage}/bin/keybash" check-tls --tls-cert=/etc/keybash/tls/cert.pem --tls-key=/etc/keybash/tls/key.pem --listen="${listen}" ${exposure} >/dev/null ||
  refuse 'TLS pair refused by the new version (keybash check-tls)'
new_rdp=''
if test "${rdp}" = yes; then
  # The runtime is prepared beside the installed one, owned and moded as
  # install.sh leaves it, so its inventory is the one the manager will check.
  cp -R -- "${stage}/runtime" "${runtime}.new"
  chown -R root:root "${runtime}.new"
  chmod -R go-w "${runtime}.new"
  test -z "$(find "${runtime}.new" -type l -print -quit)" || refuse 'prepared runtime contains a symlink'
  new_runtime="$("${stage}/bin/keybash-rdp-inventory" "${runtime}.new")" || refuse 'the new RDP runtime was refused'
  new_rdp="--rdp-worker-digest=$(digest "${stage}/bin/keybash-rdp-worker") --rdp-runtime-digest=${new_runtime}"
fi
new_worker="$(digest "${stage}/bin/keybash-ssh-worker")"
# shellcheck disable=SC2086
"${stage}/bin/keybash-service-plan" ${kept} --worker-digest="${new_worker}" ${new_rdp} --listen="${listen}" ${exposure} \
  --output="${work}/plan" >/dev/null || refuse 'the new service plan refused this installation'"'"'s settings'
cmp -s "${work}/plan/keybash.conf" /etc/sysusers.d/keybash.conf || refuse 'the new plan changes the service accounts; reinstall instead'
planned=''
for unit in ${units}; do planned="${planned} ${work}/plan/${unit}"; done
# shellcheck disable=SC2086 # planned holds fixed unit names under the private work directory
systemd-analyze verify ${planned} >/dev/null || refuse 'the new units do not verify (systemd-analyze verify)'
revision=''
if test -f "${stage}/source-revision"; then
  revision="$(head -c 41 "${stage}/source-revision" | tr -d '\n')"
  printf '%s\n' "${revision}" | grep -Eqx '[0-9a-f]{40}' || revision=''
fi
backup="${backups}/$(date -u +%Y%m%dT%H%M%SZ)"
test ! -e "${backup}" && test ! -L "${backup}" || refuse "${backup} already exists; wait a second and run again"

# --- Upgrade: the first change -------------------------------------------------
changed=yes
test -d /var/backups || install -d -o root -g root -m 0755 /var/backups
test -d "${backups}" || install -d -o root -g root -m 0700 "${backups}"
install -d -o root -g root -m 0700 "${backup}" "${backup}/bin" "${backup}/units"
for program in ${programs}; do cp -p -- "${libexec}/${program}" "${backup}/bin/${program}"; done
for unit in ${units}; do cp -p -- "${systemd}/${unit}" "${backup}/units/${unit}"; done
if test "${rdp}" = yes; then cp -Rp -- "${runtime}" "${backup}/runtime"; fi
stopped=yes
# shellcheck disable=SC2086
systemctl stop ${enabled}
cp -p -- "${database}" "${backup}/custody.db"
cmp -s "${database}" "${backup}/custody.db" || fail 'the database copy differs from the database'

swapped=yes
for program in ${programs}; do
  install -o root -g root -m 0755 "${stage}/bin/${program}" "${libexec}/${program}.new"
  mv -f -- "${libexec}/${program}.new" "${libexec}/${program}"
  test "$(digest "${libexec}/${program}")" = "$(digest "${stage}/bin/${program}")" || fail "${program} changed while upgrading"
done
test "$(digest "${libexec}/keybash-ssh-worker")" = "${new_worker}" || fail 'SSH worker changed while upgrading'
if test "${rdp}" = yes; then
  mv -- "${runtime}" "${runtime}.old"
  mv -- "${runtime}.new" "${runtime}"
fi
for unit in ${units}; do install -o root -g root -m 0644 "${work}/plan/${unit}" "${systemd}/${unit}"; done
systemctl daemon-reload
started=yes
# shellcheck disable=SC2086
systemctl start ${enabled} || fail 'the new version did not start'
ready || fail 'the new version did not come up'
if test "${rdp}" = yes; then rm -rf -- "${runtime}.old"; fi

printf '%s\n' "Keybash is upgraded and running${revision:+ (source ${revision})}." \
  "The previous programs, units and database are in ${backup}." \
  'Remove that directory once the new version works for you.'
