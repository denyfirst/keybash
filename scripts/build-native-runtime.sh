#!/bin/sh
# Build source-test native components only. No install/start/release operation.
set -eu
repo="$(pwd)"
if test "$#" -lt 1 || test "$#" -gt 2; then echo 'usage: build-native-runtime.sh NEW_ABSOLUTE_PREFIX [--fixtures]' >&2; exit 1; fi
prefix="$1"
fixtures=OFF
if test "$#" = 2; then test "$2" = --fixtures; fixtures=ON; fi
test "$(uname -sm)" = 'Linux x86_64'
test "${prefix}" = "$(realpath -m -- "${prefix}")"
if test "${fixtures}" = ON; then
  case "${prefix}" in /tmp/keybash-native.??????/prefix) lab="$(dirname -- "${prefix}")" ;; *) echo 'fixtures require the disposable CI prefix' >&2; exit 1 ;; esac
  test -d "${prefix}/bin"
else
  test ! -e "${prefix}"
  mkdir -m 755 -- "${prefix}"
  lab="$(mktemp -d /tmp/keybash-native-build.XXXXXX)"
  trap 'rm -rf "${lab}"' EXIT
fi
test ! -e "${lab}/freerdp-3.32.2"
test ! -e "${lab}/guacamole-server-1.6.0"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.3 \
  https://github.com/FreeRDP/FreeRDP/releases/download/3.32.2/freerdp-3.32.2.tar.gz -o "${lab}/freerdp.tar.gz"
printf '%s  %s\n' e95a505c0057e4d06a3b120477c421028769deba4db9c639ef3465d050f0955c "${lab}/freerdp.tar.gz" | sha256sum -c -
curl --fail --silent --show-error --location --proto '=https' --tlsv1.3 \
  https://archive.apache.org/dist/guacamole/1.6.0/source/guacamole-server-1.6.0.tar.gz -o "${lab}/guacamole.tar.gz"
printf '%s  %s\n' 8bc45675da96d7b6f39728160181e3d4ff3c08f460f6d26de5805b642bf13f2b "${lab}/guacamole.tar.gz" | sha256sum -c -
tar -xf "${lab}/freerdp.tar.gz" -C "${lab}"
tar -xf "${lab}/guacamole.tar.gz" -C "${lab}"
python3 native/prepare.py "${lab}/freerdp-3.32.2" "${lab}/guacamole-server-1.6.0" "${repo}/native/identity.c"
cmake -S native -B "${lab}/identity-build"
cmake --build "${lab}/identity-build" --parallel 2
# Analyze our identity callback separately from the upstream library build.
clang --analyze -std=c11 -Wall -Wextra -Werror -Xanalyzer -analyzer-output=text \
  "${repo}/native/identity.c" -o "${lab}/identity-analysis.plist" 2> "${lab}/identity-analysis.log"
if test -s "${lab}/identity-analysis.log"; then
  cat "${lab}/identity-analysis.log" >&2
  exit 1
fi
cmake -S "${lab}/freerdp-3.32.2" -B "${lab}/freerdp-build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${prefix}" -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_C_FLAGS='-fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wformat -Werror=format-security' \
  -DCMAKE_EXE_LINKER_FLAGS='-Wl,-z,relro,-z,now' -DCMAKE_SHARED_LINKER_FLAGS='-Wl,-z,relro,-z,now' \
  -DBUILD_TESTING=OFF -DWITH_CLIENT=OFF -DWITH_CLIENT_COMMON=ON -DWITH_SERVER="${fixtures}" -DWITH_SAMPLE="${fixtures}" \
  -DWITH_SHADOW=OFF -DWITH_PROXY=OFF -DWITH_X11=OFF -DWITH_WAYLAND=OFF -DWITH_MANPAGES=OFF \
  -DWITH_FFMPEG=OFF -DWITH_OPENH264=OFF -DWITH_KRB5=OFF -DWITH_PCSC=OFF -DWITH_CUPS=OFF \
  -DWITH_ALSA=OFF -DWITH_PULSE=OFF -DWITH_OSS=OFF -DWITH_SWSCALE=OFF -DWITH_AAD=OFF -DWITH_FUSE=OFF \
  -DWITH_OPUS=OFF -DWITH_GSM=OFF -DWITH_LAME=OFF -DWITH_FAAC=OFF -DWITH_FAAD2=OFF \
  -DWITH_SOXR=OFF -DWITH_AOM=OFF -DWITH_DAV1D=OFF -DWITH_WEBP=OFF -DCHANNEL_URBDRC=OFF
cmake --build "${lab}/freerdp-build" --parallel 4
cmake --install "${lab}/freerdp-build"
export PKG_CONFIG_PATH="${prefix}/lib/pkgconfig"
export LD_LIBRARY_PATH="${prefix}/lib"
test "$(pkg-config --modversion freerdp3)" = 3.32.2
cd "${lab}/guacamole-server-1.6.0"
./configure --prefix="${prefix}" --with-rdp --without-ssh --without-vnc --without-telnet --without-kubernetes \
  --without-pulse --without-avcodec --without-avformat --without-avutil --without-swscale \
  CPPFLAGS="-isystem ${prefix}/include/freerdp3 -isystem ${prefix}/include/winpr3" \
  CFLAGS='-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wformat -Werror=format-security' \
  LDFLAGS='-Wl,-z,relro,-z,now' LIBS='-lssl -lcrypto'
make -j4
make install
cd "${repo}"
mkdir -p "${prefix}/share/lab"
cp "${lab}/freerdp-3.32.2/LICENSE" "${prefix}/share/lab/FREERDP-LICENSE"
cp "${lab}/guacamole-server-1.6.0/LICENSE" "${prefix}/share/lab/GUACAMOLE-LICENSE"
cp "${lab}/guacamole-server-1.6.0/NOTICE" "${prefix}/share/lab/GUACAMOLE-NOTICE"
find "${lab}/freerdp-3.32.2/server/Sample" -name 'test_icon.*' -exec cp '{}' "${prefix}/share/lab/" ';'

printf "%s\n" "Source-test native prefix prepared; no service installed."
