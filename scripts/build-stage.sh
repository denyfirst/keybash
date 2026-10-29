#!/bin/sh
# Builds a stage for scripts/install.sh, as an ordinary user, from the
# repository root. It installs nothing and never writes into an existing path.
#   build-stage.sh NEW_STAGE                 SSH only
#   build-stage.sh NEW_STAGE --with-rdp      also builds the native RDP runtime
#   build-stage.sh NEW_STAGE --rdp-runtime=DIR   reuses a runtime made by
#                                            scripts/build-rdp-runtime.py
set -eu
usage() { echo 'usage: build-stage.sh NEW_ABSOLUTE_STAGE [--with-rdp | --rdp-runtime=DIR]' >&2; exit 1; }
test "$#" -ge 1 && test "$#" -le 2 || usage
stage="$1"
rdp=no
prebuilt=''
if test "$#" = 2; then
  case "$2" in
    --with-rdp) rdp=build ;;
    --rdp-runtime=/*) rdp=copy; prebuilt="${2#*=}" ;;
    *) usage ;;
  esac
fi
test "$(id -u)" != 0 || { echo 'build as an ordinary user, not root' >&2; exit 1; }
test "$(uname -sm)" = 'Linux x86_64' || { echo 'Linux x86-64 only' >&2; exit 1; }
case "${stage}" in /*) ;; *) usage ;; esac
test "${stage}" = "$(realpath -m -- "${stage}")" || usage
test ! -e "${stage}" && test ! -L "${stage}" || { echo 'stage exists; choose a new directory' >&2; exit 1; }
grep -qx 'module github.com/denyfirst/keybash' go.mod 2>/dev/null || { echo 'run from the keybash repository root' >&2; exit 1; }
if test "${rdp}" = copy; then
  test -d "${prebuilt}" && test ! -L "${prebuilt}" || { echo 'RDP runtime is not a directory' >&2; exit 1; }
fi
go mod verify
mkdir -m 0755 -- "${stage}" "${stage}/bin"
programs='keybash keybash-ssh-manager keybash-ssh-worker keybash-service-check keybash-service-plan keybash-test-tls'
test "${rdp}" = no || programs="${programs} keybash-rdp-manager keybash-rdp-worker keybash-rdp-inventory"
for program in ${programs}; do
  CGO_ENABLED=0 go build -trimpath -o "${stage}/bin/${program}" "./cmd/${program}"
done
case "${rdp}" in
  build)
    sh scripts/build-native-runtime.sh "${stage}/native"
    LD_LIBRARY_PATH="${stage}/native/lib" python3 scripts/build-rdp-runtime.py --prefix "${stage}/native" --output "${stage}/runtime"
    ;;
  copy)
    cp -R -- "${prebuilt}" "${stage}/runtime"
    ;;
esac
git rev-parse HEAD > "${stage}/source-revision" 2>/dev/null || true
echo "Stage ready: ${stage}. Install it with: sudo sh scripts/install.sh --stage=${stage} ..."
