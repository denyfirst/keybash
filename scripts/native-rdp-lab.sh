#!/bin/sh
# CI-only native laboratory builder. No product installation or image release.
set -eu
repo="$(pwd)"
lab="$(mktemp -d /tmp/keybash-native.XXXXXX)"
trap 'rm -rf "${lab}"' EXIT
chmod 755 "${lab}"
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends build-essential clang cmake ninja-build pkg-config bubblewrap \
  libssl-dev libcairo2-dev libjpeg-dev libpng-dev libwebp-dev libpango1.0-dev libuuid1 uuid-dev
prefix="${lab}/prefix"
mkdir -p "${prefix}/bin"
# Fixed verified test Node runtime; no browser runtime enters a release.
test "$(node --version)" = v24.19.0
cp "$(command -v node)" "${prefix}/bin/node"
export KEYBASH_NATIVE_BROWSER_CACHE="${HOME}/.cache/ms-playwright"
test -d "${KEYBASH_NATIVE_BROWSER_CACHE}"
go test -c -race -tags=nativelab,browserlab -o "${prefix}/bin/lab.test" ./internal/rdplab
chmod 755 "${prefix}" "${prefix}/bin" "${prefix}/bin/lab.test"
sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" KEYBASH_NATIVE_BROWSER_CACHE="${KEYBASH_NATIVE_BROWSER_CACHE}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDPSandboxPreparation$' -test.timeout=10s -test.v
sh scripts/build-native-runtime.sh "${prefix}" --fixtures
# Exercise the same empty-prefix, server/sample-disabled build documented for
# the user's future test VM. Installed managers use this runtime; synthetic
# FreeRDP peers remain confined to the separate fixture prefix.
normal_prefix="${lab}/normal-prefix"
sh scripts/build-native-runtime.sh "${normal_prefix}"
# A dated inventory is diagnostic CI evidence, never a release/SBOM claim.
dpkg-query -W -f='${Package} ${Version}\n'
find "${prefix}" -type f -exec sha256sum '{}' ';'
ldd "${prefix}/sbin/guacd"
ldd "${prefix}/lib/libguac-client-rdp.so"
CGO_ENABLED=0 go build -trimpath -o "${prefix}/bin/keybash-rdp-worker" ./cmd/keybash-rdp-worker
for bin in keybash keybash-ssh-manager keybash-ssh-worker keybash-service-check keybash-service-plan keybash-rdp-manager; do
  CGO_ENABLED=0 go build -trimpath -o "${prefix}/bin/${bin}" "./cmd/${bin}"
done
LD_LIBRARY_PATH="${normal_prefix}/lib" python3 scripts/build-rdp-runtime.py --prefix "${normal_prefix}" --output "${prefix}/runtime-stage"
go test -c -race -tags=nativelab,browserlab -o "${prefix}/bin/lab.test" ./internal/rdplab
chmod 755 "${prefix}/bin/lab.test"
if ! sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDPManagerPublicPreflight$' -test.timeout=25s -test.v; then
  python3 scripts/rdp-preflight-diagnostics.py "${prefix}"
  overlay="${lab}/preflight-diagnostics/overlay.json"
  CGO_ENABLED=0 go build -overlay="${overlay}" -trimpath -o "${prefix}/bin/debug-worker" ./cmd/keybash-rdp-worker
  go test -c -overlay="${overlay}" -race -tags=nativelab,browserlab -o "${prefix}/bin/debug.test" ./internal/rdplab
  sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
    "${prefix}/bin/debug.test" -test.run='^TestNativeRDPManagerPublicPreflight$' -test.timeout=25s -test.v || true
  echo 'Normal candidate public preflight failed; diagnostic overlays cannot pass this gate.' >&2
  exit 1
fi
sudo -n env -i PATH=/usr/bin:/bin LD_LIBRARY_PATH="${prefix}/lib" KEYBASH_NATIVE_PREFIX="${prefix}" KEYBASH_NATIVE_BROWSER_CACHE="${KEYBASH_NATIVE_BROWSER_CACHE}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDPAuthenticationRenderingAndRevocation$/password_valid_true$' -test.timeout=25s -test.v
sudo -n env -i PATH=/usr/bin:/bin LD_LIBRARY_PATH="${prefix}/lib" KEYBASH_NATIVE_PREFIX="${prefix}" KEYBASH_NATIVE_BROWSER_CACHE="${KEYBASH_NATIVE_BROWSER_CACHE}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDP' -test.timeout=5m -test.v

# Both directions must detect sabotage on the ACTUAL native TLS callback.
# All mutations stay in this disposable extracted tree, never repository files.
guac="${lab}/guacamole-server-1.6.0"
identity="${guac}/src/protocols/rdp/keybash_identity.c"
cp "${identity}" "${lab}/identity.original"
rebuild_identity() {
  touch "${guac}/src/protocols/rdp/rdp.c"
  make -C "${guac}/src/protocols/rdp" -j4
  make -C "${guac}/src/protocols/rdp" install
}
expect_mutation_failure() {
  if sudo -n env -i PATH=/usr/bin:/bin LD_LIBRARY_PATH="${prefix}/lib" KEYBASH_NATIVE_PREFIX="${prefix}" KEYBASH_NATIVE_BROWSER_CACHE="${KEYBASH_NATIVE_BROWSER_CACHE}" \
    "${prefix}/bin/lab.test" "-test.run=$1" -test.timeout=45s -test.v > "${lab}/mutation.log" 2>&1; then
    echo 'native security mutation escaped its test' >&2
    exit 1
  fi
  cat "${lab}/mutation.log"
  grep -F "$2" "${lab}/mutation.log"
}
printf '%s\n' '#include <stddef.h>' \
  'int keybash_verify_identity(const char* p, size_t n) { (void)p; (void)n; return 1; }' > "${identity}"
rebuild_identity
expect_mutation_failure '^TestNativeRDPCertificateRefusalBeforeCredentials$/changed$' \
  'native worker sent CredSSP before certificate refusal'
printf '%s\n' '#include <stddef.h>' \
  'int keybash_verify_identity(const char* p, size_t n) { (void)p; (void)n; return 0; }' > "${identity}"
rebuild_identity
expect_mutation_failure '^TestNativeRDPAuthenticationRenderingAndRevocation$/password_valid_true$' \
  'native account did not authenticate'
cp "${lab}/identity.original" "${identity}"
cmp "${identity}" "${repo}/native/identity.c"
rebuild_identity
sudo -n env -i PATH=/usr/bin:/bin LD_LIBRARY_PATH="${prefix}/lib" KEYBASH_NATIVE_PREFIX="${prefix}" KEYBASH_NATIVE_BROWSER_CACHE="${KEYBASH_NATIVE_BROWSER_CACHE}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDP' -test.timeout=5m -test.v
