#!/bin/sh
# Stops Keybash and removes what scripts/install.sh put on this host as
# program files and units. It never deletes data: the database, the instance
# key, the TLS pair, the catalog and the two accounts stay until an operator
# removes them deliberately. Run as root.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
test "$#" = 0 || { echo 'usage: uninstall.sh (no options)' >&2; exit 1; }
test "$(id -u)" = 0 || { echo 'uninstall refused: run as root' >&2; exit 1; }
units='keybash-gateway.service keybash-rdp-manager.service keybash-ssh-manager.service'
for unit in ${units}; do
  if test -e "/etc/systemd/system/${unit}"; then
    systemctl disable --now "${unit}" || true
  fi
done
systemctl stop keybash.slice 2>/dev/null || true
for unit in ${units} keybash.slice; do
  rm -f -- "/etc/systemd/system/${unit}"
done
rm -f -- /etc/sysusers.d/keybash.conf
rm -rf -- /usr/local/libexec/keybash /usr/local/lib/keybash /run/systemd/system.control/keybash.slice.d
systemctl daemon-reload
for unit in ${units}; do systemctl reset-failed "${unit}" 2>/dev/null || true; done
printf '%s\n' 'Keybash programs and units are removed. Kept, until you delete them yourself:' \
  '  /var/lib/keybash   the database' \
  '  /etc/keybash       instance key, TLS pair and server catalog' \
  '  accounts keybash-gateway and keybash-worker' \
  'Back up first if you may need the data. A fresh install needs all of them gone.'
