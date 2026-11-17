#!/bin/sh
# Builds keybash-rdp-proxy (docs/BROWSER-RDP-PROXY.md) from rdp-proxy/ with
# its Cargo.lock and the toolchain IronRDP pins. It installs nothing and never
# writes into an existing path. The same inputs give the same bytes: CI builds
# it twice and compares the results.
#   build-rdp-proxy.sh NEW_ABSOLUTE_OUTPUT [--with-tests]
# Needs rustup with the pinned toolchain (with clippy and rustfmt for the
# tests), and python3.
set -eu
# The same toolchain as scripts/build-ironrdp-web.sh, which checks it against
# IronRDP's rust-toolchain.toml.
rust=1.94.1
usage() { echo 'usage: build-rdp-proxy.sh NEW_ABSOLUTE_OUTPUT [--with-tests]' >&2; exit 1; }
test "$#" -ge 1 && test "$#" -le 2 || usage
out="$1"
tests=no
if test "$#" = 2; then test "$2" = --with-tests || usage; tests=yes; fi
test "$(uname -sm)" = 'Linux x86_64' || { echo 'Linux x86-64 only' >&2; exit 1; }
case "${out}" in /*) ;; *) usage ;; esac
test "${out}" = "$(realpath -m -- "${out}")" || usage
test ! -e "${out}" && test ! -L "${out}" || { echo 'output exists; choose a new directory' >&2; exit 1; }
repo="$(pwd)"
test -f "${repo}/rdp-proxy/Cargo.lock" || { echo 'run from the keybash repository root' >&2; exit 1; }
# The browser and the proxy speak with the same IronRDP: every git dependency
# names the commit scripts/build-ironrdp-web.sh pins.
commit="$(sed -n 's/^commit=\([0-9a-f]\{40\}\)$/\1/p' "${repo}/scripts/build-ironrdp-web.sh")"
revs="$(grep -c 'rev = ' "${repo}/rdp-proxy/Cargo.toml")"
test -n "${commit}" && test "${revs}" -gt 0 && test "$(grep -c "rev = \"${commit}\"" "${repo}/rdp-proxy/Cargo.toml")" = "${revs}" ||
  { echo 'rdp-proxy must use the IronRDP commit build-ironrdp-web.sh pins' >&2; exit 1; }

work="$(mktemp -d /tmp/keybash-rdp-proxy.XXXXXX)"
trap 'rm -rf "${work}"' EXIT
# Fresh, private state: crates and IronRDP's commit come in checked against
# Cargo.lock; build paths are rewritten so they leave no trace.
export RUSTUP_TOOLCHAIN="${rust}"
export CARGO_HOME="${work}/cargo"
export CARGO_TARGET_DIR="${work}/target"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=${work}=/build --remap-path-prefix=${repo}=/keybash"
test "$(rustc --version | cut -d ' ' -f 2)" = "${rust}" || { echo "rustup has no Rust ${rust} toolchain" >&2; exit 1; }

cd "${repo}/rdp-proxy"
cargo fetch --locked
python3 "${repo}/scripts/rust-licences.py" --manifest "${repo}/rdp-proxy/Cargo.toml" --package keybash-rdp-proxy \
  --target x86_64-unknown-linux-gnu > "${work}/crates.txt"
if test "${tests}" = yes; then
  cargo fmt --check
  cargo clippy --locked --offline --all-targets -- -D warnings
  cargo test --locked --offline
fi
# cargo's own record of every crate it compiled, for the advisory check.
cargo build --locked --offline --release --message-format=json-render-diagnostics > "${work}/build.json"
python3 "${repo}/scripts/rust-advisories.py" built < "${work}/build.json" > "${work}/built.txt"
mkdir -m 0755 -- "${out}"
cp "${CARGO_TARGET_DIR}/release/keybash-rdp-proxy" "${out}/keybash-rdp-proxy"
cp "${work}/crates.txt" "${out}/CRATES.txt"
cp "${work}/built.txt" "${out}/BUILT.txt"
cp "${repo}/rdp-proxy/Cargo.lock" "${out}/Cargo.lock"
cd "${out}"
sha256sum -- * > "${work}/SHA256SUMS"
mv "${work}/SHA256SUMS" "${out}/SHA256SUMS"
cat "${out}/SHA256SUMS"
echo "RDP proxy ready: ${out}"
