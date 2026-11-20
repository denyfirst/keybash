#!/bin/sh
# Builds keybash-rdp-testpeer (rdp-testpeer/), a synthetic RDP server for
# Keybash's tests only: CI's proxy job and the native lab run it, and nothing
# installs it. It installs nothing and never writes into an existing path.
#   build-rdp-testpeer.sh NEW_ABSOLUTE_OUTPUT
# Needs rustup with the pinned toolchain.
set -eu
rust=1.94.1
usage() { echo 'usage: build-rdp-testpeer.sh NEW_ABSOLUTE_OUTPUT' >&2; exit 1; }
test "$#" = 1 || usage
out="$1"
test "$(uname -sm)" = 'Linux x86_64' || { echo 'Linux x86-64 only' >&2; exit 1; }
case "${out}" in /*) ;; *) usage ;; esac
test "${out}" = "$(realpath -m -- "${out}")" || usage
test ! -e "${out}" && test ! -L "${out}" || { echo 'output exists; choose a new directory' >&2; exit 1; }
repo="$(pwd)"
test -f "${repo}/rdp-testpeer/Cargo.lock" || { echo 'run from the keybash repository root' >&2; exit 1; }
# The same IronRDP commit as the browser module and the proxy.
commit="$(sed -n 's/^commit=\([0-9a-f]\{40\}\)$/\1/p' "${repo}/scripts/build-ironrdp-web.sh")"
revs="$(grep -c 'rev = ' "${repo}/rdp-testpeer/Cargo.toml")"
test -n "${commit}" && test "${revs}" -gt 0 && test "$(grep -c "rev = \"${commit}\"" "${repo}/rdp-testpeer/Cargo.toml")" = "${revs}" ||
  { echo 'rdp-testpeer must use the IronRDP commit build-ironrdp-web.sh pins' >&2; exit 1; }

work="$(mktemp -d /tmp/keybash-rdp-testpeer.XXXXXX)"
trap 'rm -rf "${work}"' EXIT
export RUSTUP_TOOLCHAIN="${rust}"
export CARGO_HOME="${work}/cargo"
export CARGO_TARGET_DIR="${work}/target"
export CARGO_INCREMENTAL=0
test "$(rustc --version | cut -d ' ' -f 2)" = "${rust}" || { echo "rustup has no Rust ${rust} toolchain" >&2; exit 1; }
cd "${repo}/rdp-testpeer"
cargo build --locked --release
mkdir -m 0755 -- "${out}"
cp "${CARGO_TARGET_DIR}/release/keybash-rdp-testpeer" "${out}/keybash-rdp-testpeer"
echo "RDP test peer ready: ${out}"
