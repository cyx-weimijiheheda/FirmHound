#!/bin/bash
# Build the intentionally-vulnerable fixture firmware.
#
# Requires: arm-linux-gnueabi-gcc, squashfs-tools (mksquashfs).
# Produces:
#   build/rootfs/            assembled root filesystem tree
#   dist/fixture-fw-v1.0.bin squashfs firmware image (analyzer input)
#
# The vulnerable daemons are compiled WITHOUT stack protector / PIE so
# binary hardening checks have something to report; the negative-control
# daemon "safed" is compiled WITH hardening for contrast. All fixture
# binaries are stripped, like production firmware.
set -euo pipefail

cd "$(dirname "$0")"
CC=arm-linux-gnueabi-gcc
STRIP=arm-linux-gnueabi-strip
OUT=build/rootfs
DIST=dist

rm -rf build "$DIST"
mkdir -p "$OUT" "$DIST"
cp -r rootfs/. "$OUT"/

VULN_CFLAGS="-O0 -fno-stack-protector -fno-pie -no-pie"
SAFE_CFLAGS="-O2 -fstack-protector-all -fPIE -pie -D_FORTIFY_SOURCE=2"

# Shared config library so wandetect carries a real nvram_get import.
$CC -O0 -fPIC -shared -o "$OUT/lib/libnvram.so" src/nvram.c

$CC $VULN_CFLAGS -o "$OUT/usr/sbin/httpd" src/httpd.c
$CC $VULN_CFLAGS -o "$OUT/usr/sbin/upnpd" src/upnpd.c
$CC $VULN_CFLAGS -o "$OUT/usr/sbin/wandetect" src/wandetect.c \
    -L"$OUT/lib" -lnvram -Wl,-rpath,/lib
$CC $SAFE_CFLAGS -o "$OUT/usr/sbin/safed" src/safed.c

$STRIP "$OUT/usr/sbin/httpd" "$OUT/usr/sbin/upnpd" \
       "$OUT/usr/sbin/wandetect" "$OUT/usr/sbin/safed" "$OUT/lib/libnvram.so"

chmod +x "$OUT/www/cgi-bin/ping.cgi" "$OUT/etc/init.d/rcS"
# Deliberately permissive fixture config (part of the test surface).
chmod 666 "$OUT/etc/config/wireless"

# Fake busybox/telnetd placeholders: enough for startup-surface listing.
printf '#!/bin/sh\n# fixture placeholder applet (not executed by tests)\n' > "$OUT/bin/busybox"
chmod +x "$OUT/bin/busybox"
ln -sf busybox "$OUT/bin/sh"
ln -sf ../bin/busybox "$OUT/usr/sbin/telnetd"

mksquashfs "$OUT" build/fixture.squashfs -noappend -comp xz -quiet
# Prepend a 116-byte vendor-style header (like the DLOB header on real
# D-Link images) so the squashfs sits at a nonzero offset and the
# unpacker takes the single carve path instead of extracting twice.
python3 - <<'PYEOF'
header = bytearray(116)
header[0:7] = b"FIXTURE"
with open("build/fixture.squashfs", "rb") as fh:
    payload = fh.read()
with open("dist/fixture-fw-v1.0.bin", "wb") as fh:
    fh.write(header)
    fh.write(payload)
PYEOF
cp -r "$OUT" "$DIST/rootfs"

echo "built: $DIST/fixture-fw-v1.0.bin"
ls -l "$DIST/fixture-fw-v1.0.bin"
