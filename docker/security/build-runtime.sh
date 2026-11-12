#!/bin/sh
set -eu

# Security backports from OpenSSL, not an unreleased version number.
# Every source archive and upstream patch is checked before compilation.
apk upgrade --no-cache
apk add --no-cache build-base perl curl git cargo rust pkgconf libffi-dev openssl-dev expat-dev=2.10.0-r0
mkdir -p /work /out-runtime/usr/lib /out-runtime/usr/share/licenses/security-runtime /wheels
cd /work
curl -fsSL --retry 3 -o openssl.tar.gz https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz
echo '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a  openssl.tar.gz' | sha256sum -c -
tar -xzf openssl.tar.gz
cd openssl-3.5.9
(cd /security/patches && sha256sum -c SHA256SUMS)
while read -r checksum patchfile; do
    git apply --check "/security/patches/$patchfile"
    git apply "/security/patches/$patchfile"
done < /security/patches/SHA256SUMS
./Configure --prefix=/usr --libdir=lib --openssldir=/etc/ssl shared no-tests no-docs
make -j2
cp libcrypto.so.3 libssl.so.3 /out-runtime/usr/lib/
cp LICENSE.txt /out-runtime/usr/share/licenses/security-runtime/OpenSSL-LICENSE.txt
cp /security/patches/SHA256SUMS /out-runtime/usr/share/licenses/security-runtime/OPENSSL-PATCHES.sha256
cp /security/patches/*.patch /out-runtime/usr/share/licenses/security-runtime/
# The builder and the final image use these same patched shared libraries.
cp libcrypto.so.3 libssl.so.3 /usr/lib/

# Rebuild only Python's XML extension against the maintained system Expat.
# Updating an unrelated APK cannot fix a statically bundled pyexpat copy.
cd /work
curl -fsSL --retry 3 -o python.tar.xz https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tar.xz
echo 'b5796915dc45ff745cfb4e990a7e7c93d6f546328a102ce31448d69ebc37575c  python.tar.xz' | sha256sum -c -
tar -xJf python.tar.xz
mkdir -p /work/expat-config /out-runtime/usr/local/lib/python3.12/lib-dynload
cp Python-3.12.16/Modules/expat/expat_config.h /work/expat-config/
extension="$(python3 -c 'import sysconfig;print(sysconfig.get_config_var("EXT_SUFFIX"))')"
cc -shared -fPIC $(python3-config --cflags) \
    -I/usr/local/include/python3.12/internal -I/work/expat-config \
    Python-3.12.16/Modules/pyexpat.c -lexpat \
    -o "/out-runtime/usr/local/lib/python3.12/lib-dynload/pyexpat$extension"
PYTHONPATH=/out-runtime/usr/local/lib/python3.12/lib-dynload python3 -c \
    'import pyexpat,xml.etree.ElementTree as E;assert pyexpat.version_info >= (2,10,0);assert E.fromstring("<ok/>").tag=="ok"'

# Build cryptography without a second, statically bundled OpenSSL. Its source
# is pinned; the resulting wheel is checked again before installation.
curl -fsSL --retry 3 -o cryptography.tar.gz https://files.pythonhosted.org/packages/9d/af/182eb91b0df3fe75c4d9f26fe70684569566745f6ba7e5c9c73a862c5252/cryptography-50.0.2.tar.gz
echo '7b46165bb56eb4704e2eaaf86f3c940d19154535d9b0ca7d6d590b04060e00d5  cryptography.tar.gz' | sha256sum -c -
OPENSSL_STATIC=0 CARGO_BUILD_JOBS=2 python3 -m pip wheel --no-cache-dir --no-deps \
    --no-binary cryptography --wheel-dir /wheels /work/cryptography.tar.gz
(cd /wheels && sha256sum *.whl > SHA256SUMS)
printf '%s\n' 'OpenSSL 3.5.9 + official security fixes published 2026-11-10' \
    'CPython 3.12.16; pyexpat dynamically linked with system Expat >= 2.10.0' \
    'cryptography 50.0.2 dynamically linked with patched system OpenSSL' \
    > /out-runtime/usr/share/licenses/security-runtime/BUILD.txt
