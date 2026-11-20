#!/bin/sh
# CI-only native laboratory builder. No product installation or image release.
set -eu
repo="$(pwd)"
lab="$(mktemp -d /tmp/keybash-native.XXXXXX)"
trap 'rm -rf "${lab}"' EXIT
chmod 755 "${lab}"
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends bubblewrap
prefix="${lab}/prefix"
mkdir -p "${prefix}/bin"
go test -c -race -tags=nativelab -o "${prefix}/bin/lab.test" ./internal/rdplab
chmod 755 "${prefix}" "${prefix}/bin" "${prefix}/bin/lab.test"
sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDPSandboxPreparation$' -test.timeout=10s -test.v
for bin in keybash keybash-ssh-manager keybash-ssh-worker keybash-service-check keybash-service-plan keybash-rdp-manager keybash-rdp-worker; do
  CGO_ENABLED=0 go build -trimpath -o "${prefix}/bin/${bin}" "./cmd/${bin}"
done
# Keybash's RDP proxy, which every desktop runs, and the test peer it meets
# (IronRDP's own server, rdp-testpeer/), with the toolchain IronRDP pins.
rustup toolchain install 1.94.1 --profile minimal
sh scripts/build-rdp-proxy.sh "${lab}/proxy"
sh scripts/build-rdp-testpeer.sh "${lab}/peer"
cp "${lab}/peer/keybash-rdp-testpeer" "${prefix}/bin/keybash-rdp-testpeer"
python3 scripts/build-rdp-runtime.py --proxy "${lab}/proxy/keybash-rdp-proxy" --output "${prefix}/runtime-stage"
# A dated inventory is diagnostic CI evidence, never a release/SBOM claim.
find "${prefix}/runtime-stage" -type f -exec sha256sum '{}' ';'
ldd "${prefix}/runtime-stage/opt/keybash-rdp/bin/keybash-rdp-proxy"
preflight_failed=0
if ! sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDPManagerPublicPreflight$' -test.timeout=25s -test.v; then
  python3 scripts/rdp-preflight-diagnostics.py "${prefix}"
  overlay="${lab}/preflight-diagnostics/overlay.json"
  CGO_ENABLED=0 go build -overlay="${overlay}" -trimpath -o "${prefix}/bin/debug-worker" ./cmd/keybash-rdp-worker
  go test -c -overlay="${overlay}" -race -tags=nativelab -o "${prefix}/bin/debug.test" ./internal/rdplab
  sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
    "${prefix}/bin/debug.test" -test.run='^TestNativeRDPManagerPublicPreflight$' -test.timeout=25s -test.v || true
  echo 'Normal candidate public preflight failed; diagnostic overlays cannot pass this gate.' >&2
  preflight_failed=1
fi
# Collect every normal native/service boundary even if public manager
# preparation failed. Overlays never run these credential-bearing fixtures;
# any normal failure stops the gate before mutation/acceptance conclusions.
if ! sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDP' -test.timeout=8m -test.v; then
  preflight_failed=1
fi
test "${preflight_failed}" = 0
# Observe both directions on the actual manager/helper syscall boundary. These
# public-only overlays cannot send credentials or satisfy a normal test gate.
python3 scripts/rdp-sandbox-mutations.py "${prefix}"
for mutation in allow refuse; do
  go test -c -overlay="${lab}/sandbox-mutations/${mutation}.json" -race -tags=nativelab -o "${prefix}/bin/mutation.test" ./internal/rdplab
  if sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
    "${prefix}/bin/mutation.test" -test.run='^TestNativeRDPManagerPublicPreflight$' -test.timeout=25s -test.v > "${lab}/sandbox-${mutation}.log" 2>&1; then
    echo 'RDP sandbox mutation escaped its positive preflight test' >&2
    exit 1
  fi
  cat "${lab}/sandbox-${mutation}.log"
  grep -F 'public-only managed preflight refused' "${lab}/sandbox-${mutation}.log"
done

# Both directions must detect sabotage of the proxy's own pin, in the sandbox,
# on the native test that meets it. Each mutant is built from a disposable
# copy of rdp-proxy/; the repository's files are never changed.
mutant_proxy() {
  rm -rf "${lab}/mutant"
  mkdir -p "${lab}/mutant"
  cp -R "${repo}/rdp-proxy" "${repo}/scripts" "${lab}/mutant/"
  pin="${lab}/mutant/rdp-proxy/src/pin.rs"
  session="${lab}/mutant/rdp-proxy/src/session.rs"
  sed -i "$1" "${pin}"
  sed -i "$2" "${session}"
  if cmp -s "${pin}" "${repo}/rdp-proxy/src/pin.rs" || cmp -s "${session}" "${repo}/rdp-proxy/src/session.rs"; then
    echo 'proxy pin mutation did not apply' >&2
    exit 1
  fi
  (cd "${lab}/mutant" && sh scripts/build-rdp-proxy.sh "${lab}/mutant/out")
  rm -rf "${lab}/mutant-runtime"
  python3 scripts/build-rdp-runtime.py --proxy "${lab}/mutant/out/keybash-rdp-proxy" --output "${lab}/mutant-runtime"
  mv "${prefix}/runtime-stage" "${prefix}/runtime-normal"
  mv "${lab}/mutant-runtime" "${prefix}/runtime-stage"
  if sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
    "${prefix}/bin/lab.test" -test.run='^TestNativeRDPManagerProxyMeetsNLAInTheSandbox$' -test.timeout=5m -test.v > "${lab}/mutation.log" 2>&1; then
    echo 'proxy pin mutation escaped its native test' >&2
    exit 1
  fi
  rm -rf "${prefix}/runtime-stage"
  mv "${prefix}/runtime-normal" "${prefix}/runtime-stage"
  cat "${lab}/mutation.log"
  grep -F "$3" "${lab}/mutation.log"
}
# Any certificate passes: the native refusals see credentials leave.
mutant_proxy 's/if end_entity.as_ref() != self.pinned.as_slice() {/if false {/' \
  's/    if leaf != trust.certificate {/    if false {/' \
  'the proxy sent CredSSP before its certificate refusal'
# No certificate passes: the pinned server's desktop never opens.
mutant_proxy 's/if end_entity.as_ref() != self.pinned.as_slice() {/if true {/' \
  's/    if leaf != trust.certificate {/    if true {/' \
  'no RDCleanPath response with the pinned certificate'
sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDP' -test.timeout=8m -test.v

# The installer's RDP path, with the same runtime the managers use.
sh scripts/install-lab.sh "${prefix}/runtime-stage"
