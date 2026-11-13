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
test "$(node --version)" = v26.13.1
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
preflight_failed=0
if ! sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDPManagerPublicPreflight$' -test.timeout=25s -test.v; then
  python3 scripts/rdp-preflight-diagnostics.py "${prefix}"
  overlay="${lab}/preflight-diagnostics/overlay.json"
  CGO_ENABLED=0 go build -overlay="${overlay}" -trimpath -o "${prefix}/bin/debug-worker" ./cmd/keybash-rdp-worker
  go test -c -overlay="${overlay}" -race -tags=nativelab,browserlab -o "${prefix}/bin/debug.test" ./internal/rdplab
  sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
    "${prefix}/bin/debug.test" -test.run='^TestNativeRDPManagerPublicPreflight$' -test.timeout=25s -test.v || true
  echo 'Normal candidate public preflight failed; diagnostic overlays cannot pass this gate.' >&2
  preflight_failed=1
fi
# Collect every normal native/browser/service boundary even if public manager
# preparation failed. Overlays never run these credential-bearing fixtures;
# any normal failure stops the gate before mutation/acceptance conclusions.
if ! sudo -n env -i PATH=/usr/bin:/bin LD_LIBRARY_PATH="${prefix}/lib" KEYBASH_NATIVE_PREFIX="${prefix}" KEYBASH_NATIVE_BROWSER_CACHE="${KEYBASH_NATIVE_BROWSER_CACHE}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDP' -test.timeout=5m -test.v; then
  preflight_failed=1
fi
test "${preflight_failed}" = 0
# Observe both directions on the actual manager/helper syscall boundary. These
# public-only overlays cannot send credentials or satisfy a normal test gate.
python3 scripts/rdp-sandbox-mutations.py "${prefix}"
for mutation in allow refuse; do
  go test -c -overlay="${lab}/sandbox-mutations/${mutation}.json" -race -tags=nativelab,browserlab -o "${prefix}/bin/mutation.test" ./internal/rdplab
  if sudo -n env -i PATH=/usr/bin:/bin KEYBASH_NATIVE_PREFIX="${prefix}" \
    "${prefix}/bin/mutation.test" -test.run='^TestNativeRDPManagerPublicPreflight$' -test.timeout=25s -test.v > "${lab}/sandbox-${mutation}.log" 2>&1; then
    echo 'RDP sandbox mutation escaped its positive preflight test' >&2
    exit 1
  fi
  cat "${lab}/sandbox-${mutation}.log"
  grep -F 'public-only managed preflight refused' "${lab}/sandbox-${mutation}.log"
done

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
# The exact-certificate rules, in both directions and for each thing they relax.
mutate_identity() {
  cp "${lab}/identity.original" "${identity}"
  sed -i "$1" "${identity}"
  if cmp -s "${identity}" "${lab}/identity.original"; then
    echo 'native identity mutation did not apply' >&2
    exit 1
  fi
  rebuild_identity
}
# Every server treated as exact: a certificate for another name passes.
mutate_identity 's/^    const int exact = .*$/    const int exact = 1;/'
expect_mutation_failure '^TestNativeRDPCertificateRefusalBeforeCredentials$/name$' \
  'native worker sent CredSSP before certificate refusal'
# No server treated as exact: Windows' own certificate is refused.
mutate_identity 's/^    const int exact = .*$/    const int exact = 0;/'
expect_mutation_failure '^TestNativeRDPExactCertificateAuthenticates$' \
  'native account did not authenticate'
# Part of the mark is enough: a cut name file turns the name check off.
mutate_identity 's/^    const int exact = .*$/    const int exact = size >= 1 \&\& name[0] == 0x40;/'
expect_mutation_failure '^TestNativeRDPCertificateRefusalBeforeCredentials$/exact-cut$' \
  'native worker sent CredSSP before certificate refusal'
# Key encipherment passes for a name too.
mutate_identity 's/(exact ? (KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT) : KU_DIGITAL_SIGNATURE)/(KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT)/'
expect_mutation_failure '^TestNativeRDPCertificateRefusalBeforeCredentials$/windows-named$' \
  'native worker sent CredSSP before certificate refusal'
# Only digital signature passes: Windows' own certificate is refused.
mutate_identity 's/(exact ? (KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT) : KU_DIGITAL_SIGNATURE)/KU_DIGITAL_SIGNATURE/'
expect_mutation_failure '^TestNativeRDPExactCertificateAuthenticates$' \
  'native account did not authenticate'
cp "${lab}/identity.original" "${identity}"
cmp "${identity}" "${repo}/native/identity.c"
rebuild_identity
sudo -n env -i PATH=/usr/bin:/bin LD_LIBRARY_PATH="${prefix}/lib" KEYBASH_NATIVE_PREFIX="${prefix}" KEYBASH_NATIVE_BROWSER_CACHE="${KEYBASH_NATIVE_BROWSER_CACHE}" \
  "${prefix}/bin/lab.test" -test.run='^TestNativeRDP' -test.timeout=5m -test.v

# The installer's RDP path, with the same normal runtime the managers use.
sh scripts/install-lab.sh "${prefix}/runtime-stage"
