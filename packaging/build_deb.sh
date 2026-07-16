#!/usr/bin/env bash
# Build a self-contained AutoSOC .deb (Debian/Ubuntu).
#
# It bundles the PyInstaller one-file binary (no Python needed on the target),
# installs it to /opt/autosoc, and adds a launcher + desktop entry. The only
# runtime OS dependencies are nmap and libpcap (for scanning / packet capture).
#
# Usage:  ./packaging/build_deb.sh [version]
set -euo pipefail

VERSION="${1:-3.0.0}"
ARCH="$(dpkg --print-architecture)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="autosoc_${VERSION}_${ARCH}"
STAGE="${ROOT}/dist/${PKG}"

echo "==> Building PyInstaller binary"
if [ ! -x "${ROOT}/dist/AutoSOC" ]; then
    "${ROOT}/.venv/bin/pyinstaller" --clean --noconfirm "${ROOT}/main.spec"
fi

echo "==> Staging package tree at ${STAGE}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}/DEBIAN" \
         "${STAGE}/opt/autosoc" \
         "${STAGE}/usr/bin" \
         "${STAGE}/usr/share/applications" \
         "${STAGE}/usr/share/icons/hicolor/256x256/apps"

install -m 0755 "${ROOT}/dist/AutoSOC" "${STAGE}/opt/autosoc/AutoSOC"
install -m 0644 "${ROOT}/assets/app_icon.png" "${STAGE}/usr/share/icons/hicolor/256x256/apps/autosoc.png"

# Launcher: firewall/log features need root, so offer pkexec elevation.
cat > "${STAGE}/usr/bin/autosoc" <<'LAUNCH'
#!/usr/bin/env bash
# Run AutoSOC. Pass --root (or set AUTOSOC_ELEVATE=1) to elevate for firewall,
# brute-force log reading, and endpoint isolation.
BIN=/opt/autosoc/AutoSOC
if [ "${1:-}" = "--root" ] || [ "${AUTOSOC_ELEVATE:-0}" = "1" ]; then
    shift || true
    exec pkexec env DISPLAY="$DISPLAY" XAUTHORITY="$XAUTHORITY" "$BIN" "$@"
fi
exec "$BIN" "$@"
LAUNCH
chmod 0755 "${STAGE}/usr/bin/autosoc"

cat > "${STAGE}/usr/share/applications/autosoc.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=AutoSOC
Comment=AI-native SOC: scan, detect, respond
Exec=autosoc
Icon=autosoc
Terminal=false
Categories=System;Security;Network;
DESKTOP

INSTALLED_KB="$(du -ks "${STAGE}/opt" | cut -f1)"

cat > "${STAGE}/DEBIAN/control" <<CONTROL
Package: autosoc
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Depends: nmap, libpcap0.8
Recommends: policykit-1
Installed-Size: ${INSTALLED_KB}
Maintainer: AutoSOC <security@autosoc.local>
Description: AutoSOC AI - desktop cybersecurity operations console
 AI-native SOC in a box: network scanning, MITRE-mapped detection rules,
 endpoint agents, anti-phishing, and one-click response (isolate/block).
CONTROL

cat > "${STAGE}/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q || true
gtk-update-icon-cache -q /usr/share/icons/hicolor 2>/dev/null || true
echo "AutoSOC installed. Launch it from your menu or run 'autosoc'."
echo "For firewall/isolation features, run 'autosoc --root'."
exit 0
POSTINST
chmod 0755 "${STAGE}/DEBIAN/postinst"

echo "==> Building .deb"
dpkg-deb --root-owner-group --build "${STAGE}" "${ROOT}/dist/${PKG}.deb"
echo "==> Done: dist/${PKG}.deb"
