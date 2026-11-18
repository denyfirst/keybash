#!/bin/sh
# Builds IronRDP's browser client (WebAssembly) from its pinned commit with
# Keybash's patch, for the desktop page of ADR 0008. It installs nothing and
# never writes into an existing path. The same inputs give the same bytes:
# CI builds it twice in different directories and compares the results.
#   build-ironrdp-web.sh NEW_ABSOLUTE_OUTPUT [--with-tests]
# Needs git, rustup with the pinned toolchain and its wasm32 target,
# wasm-bindgen at the version below, and python3.
set -eu
# IronRDP's master after its newest release, ironrdp-v0.17.0. The browser
# build's graphics pipeline exists only on master.
commit=abfc97b299f04622cb7860f344a35bbea9bd4361
# The toolchain IronRDP's own rust-toolchain.toml names at that commit, and
# the wasm-bindgen its Cargo.lock holds: the CLI must match the library.
rust=1.94.1
bindgen=0.2.129
usage() { echo 'usage: build-ironrdp-web.sh NEW_ABSOLUTE_OUTPUT [--with-tests]' >&2; exit 1; }
test "$#" -ge 1 && test "$#" -le 2 || usage
out="$1"
tests=no
if test "$#" = 2; then test "$2" = --with-tests || usage; tests=yes; fi
test "$(uname -sm)" = 'Linux x86_64' || { echo 'Linux x86-64 only' >&2; exit 1; }
case "${out}" in /*) ;; *) usage ;; esac
test "${out}" = "$(realpath -m -- "${out}")" || usage
test ! -e "${out}" && test ! -L "${out}" || { echo 'output exists; choose a new directory' >&2; exit 1; }
repo="$(pwd)"
test -f "${repo}/ironrdp/graphics-pipeline.diff" || { echo 'run from the keybash repository root' >&2; exit 1; }

work="$(mktemp -d /tmp/keybash-ironrdp.XXXXXX)"
trap 'rm -rf "${work}"' EXIT
src="${work}/ironrdp"
git init -q "${src}"
git -C "${src}" fetch -q --depth 1 https://github.com/Devolutions/IronRDP.git "${commit}"
git -C "${src}" -c advice.detachedHead=false checkout -q FETCH_HEAD
test "$(git -C "${src}" rev-parse HEAD)" = "${commit}" || { echo "IronRDP did not check out at ${commit}" >&2; exit 1; }
grep -qx "channel = \"${rust}\"" "${src}/rust-toolchain.toml" || { echo "IronRDP at this commit does not name Rust ${rust}" >&2; exit 1; }
git -C "${src}" apply --check "${repo}/ironrdp/graphics-pipeline.diff"
git -C "${src}" apply "${repo}/ironrdp/graphics-pipeline.diff"
locked="$(awk '$0 == "name = \"wasm-bindgen\"" { getline; gsub(/version = |"/, ""); print; exit }' "${src}/Cargo.lock")"
test "${locked}" = "${bindgen}" || { echo "IronRDP's Cargo.lock holds wasm-bindgen ${locked}, not ${bindgen}" >&2; exit 1; }
test "$(wasm-bindgen --version 2>/dev/null)" = "wasm-bindgen ${bindgen}" || { echo "wasm-bindgen ${bindgen} is needed on PATH" >&2; exit 1; }

# Fresh, private state: crates come from crates.io and are checked against the
# Cargo.lock checksums; build paths are rewritten so they leave no trace.
export RUSTUP_TOOLCHAIN="${rust}"
export CARGO_HOME="${work}/cargo"
export CARGO_TARGET_DIR="${work}/target"
export CARGO_INCREMENTAL=0
test "$(rustc --version | cut -d ' ' -f 2)" = "${rust}" || { echo "rustup has no Rust ${rust} toolchain" >&2; exit 1; }
# IronRDP's own release flags for its browser build (xtask web), plus the
# path rewrite; RUSTFLAGS replaces its .cargo/config.toml, so the getrandom
# backend is repeated here.
export RUSTFLAGS="-Ctarget-feature=+simd128,+bulk-memory --cfg getrandom_backend=\"wasm_js\" -Copt-level=s -Ccodegen-units=1 -Cllvm-args=-enable-dfa-jump-thread --remap-path-prefix=${work}=/build"

cd "${src}"
cargo fetch --locked
python3 "${repo}/scripts/rust-licences.py" --manifest "${src}/Cargo.toml" --package ironrdp-web \
  --target wasm32-unknown-unknown > "${work}/crates.txt"
if test "${tests}" = yes; then
  # Keybash's patch changes the pipeline client, whose own tests run natively.
  env -u RUSTFLAGS cargo test --locked --offline -p ironrdp-egfx
fi
# cargo's own record of every crate it compiled, for the advisory check.
cargo build --locked --offline --release --target wasm32-unknown-unknown -p ironrdp-web \
  --message-format=json-render-diagnostics > "${work}/build.json"
python3 "${repo}/scripts/rust-advisories.py" built < "${work}/build.json" > "${work}/built.txt"
mkdir -m 0755 -- "${out}"
wasm-bindgen --target web --no-typescript --out-dir "${out}" \
  "${CARGO_TARGET_DIR}/wasm32-unknown-unknown/release/ironrdp_web.wasm"
cp "${src}/LICENSE-MIT" "${out}/IRONRDP-LICENSE-MIT"
cp "${src}/LICENSE-APACHE" "${out}/IRONRDP-LICENSE-APACHE"
cp "${work}/crates.txt" "${out}/CRATES.txt"
cp "${work}/built.txt" "${out}/BUILT.txt"
cp "${src}/Cargo.lock" "${out}/Cargo.lock"
cd "${out}"
sha256sum -- * > "${work}/SHA256SUMS"
mv "${work}/SHA256SUMS" "${out}/SHA256SUMS"
cat "${out}/SHA256SUMS"
echo "IronRDP browser client ready: ${out}"
