#!/usr/bin/env bash
set -euo pipefail

# LogIntel Debian Package Builder
# Builds the frontend, compiles the Tauri shell, packages the Python engine,
# and generates a standalone .deb installer using standard Debian packaging.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="0.1.0"
PACKAGE_NAME="logintel"
DEB_DIR="${ROOT_DIR}/build/deb"
OUTPUT_DIR="${ROOT_DIR}/packaging/deb"
DEB_FILE="${OUTPUT_DIR}/${PACKAGE_NAME}_${VERSION}_amd64.deb"

echo "=== [1/5] Building Desktop Frontend (Vite + TypeScript) ==="
cd "${ROOT_DIR}/apps/desktop"
npm run build

echo "=== [2/5] Compiling Tauri Desktop Binary (Cargo Release) ==="
cd "${ROOT_DIR}/apps/desktop/src-tauri"
cargo build --release

echo "=== [3/5] Staging Debian Package Structure ==="
rm -rf "${DEB_DIR}"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/bin"
mkdir -p "${DEB_DIR}/usr/lib/logintel/engine"
mkdir -p "${DEB_DIR}/usr/share/applications"
mkdir -p "${DEB_DIR}/usr/share/icons/hicolor/128x128/apps"
mkdir -p "${DEB_DIR}/usr/share/doc/logintel"
mkdir -p "${OUTPUT_DIR}"

# 1. Install desktop binary
cp "${ROOT_DIR}/apps/desktop/src-tauri/target/release/app" "${DEB_DIR}/usr/bin/logintel-bin"
chmod 755 "${DEB_DIR}/usr/bin/logintel-bin"

# 2. Install Python engine source
cp -r "${ROOT_DIR}/apps/engine/src/logintel" "${DEB_DIR}/usr/lib/logintel/engine/"
cp "${ROOT_DIR}/apps/engine/requirements.txt" "${DEB_DIR}/usr/lib/logintel/engine/"
cp "${ROOT_DIR}/apps/engine/pyproject.toml" "${DEB_DIR}/usr/lib/logintel/engine/"

# 3. Create wrapper script in /usr/bin/logintel
cat << 'EOF' > "${DEB_DIR}/usr/bin/logintel"
#!/usr/bin/env bash
set -e
export PYTHONPATH="/usr/lib/logintel/engine:${PYTHONPATH:-}"
exec /usr/bin/logintel-bin "$@"
EOF
chmod 755 "${DEB_DIR}/usr/bin/logintel"

# 4. Install Desktop Entry & Icon
cp "${ROOT_DIR}/packaging/deb/logintel.desktop" "${DEB_DIR}/usr/share/applications/logintel.desktop"
chmod 644 "${DEB_DIR}/usr/share/applications/logintel.desktop"
cp "${ROOT_DIR}/apps/desktop/src-tauri/icons/128x128.png" "${DEB_DIR}/usr/share/icons/hicolor/128x128/apps/logintel.png"
chmod 644 "${DEB_DIR}/usr/share/icons/hicolor/128x128/apps/logintel.png"

# 5. Install Documentation and Copyright
cat << EOF > "${DEB_DIR}/usr/share/doc/logintel/copyright"
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: LogIntel
Source: https://github.com/logintel/logintel

Files: *
Copyright: 2026 LogIntel Team
License: Proprietary
EOF

# 6. Generate DEBIAN/control
INSTALLED_SIZE=$(du -sk "${DEB_DIR}" | awk '{print $1}')
cat << EOF > "${DEB_DIR}/DEBIAN/control"
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Installed-Size: ${INSTALLED_SIZE}
Maintainer: LogIntel Team <dev@logintel.local>
Depends: libwebkit2gtk-4.1-0, libgtk-3-0t64 | libgtk-3-0, python3 (>= 3.10)
Description: Linux Security Telemetry & Investigation Platform
 LogIntel transforms raw Linux telemetry from journald, auth.log, syslog,
 and kern.log into structured, searchable, evidence-backed security investigations.
 Operates 100% locally with zero external network dependencies.
EOF

# 7. Generate DEBIAN/postinst
cat << 'EOF' > "${DEB_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
    # Update desktop and icon databases if tools are available
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
    fi
    
    echo "=========================================================="
    echo " LogIntel has been installed successfully!"
    echo " Ensure your user is a member of the 'adm' group to read"
    echo " system security telemetry without root privileges:"
    echo "   sudo usermod -aG adm \$USER"
    echo " Then launch LogIntel from your applications menu or type:"
    echo "   logintel"
    echo "=========================================================="
fi
exit 0
EOF
chmod 755 "${DEB_DIR}/DEBIAN/postinst"

# 8. Generate DEBIAN/prerm
cat << 'EOF' > "${DEB_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e
# Kill any lingering user engine processes on uninstall
pkill -f "logintel.main" || true
exit 0
EOF
chmod 755 "${DEB_DIR}/DEBIAN/prerm"

echo "=== [4/5] Assembling Debian Package with dpkg-deb ==="
dpkg-deb --build --root-owner-group "${DEB_DIR}" "${DEB_FILE}"

echo "=== [5/5] Verifying Package Artifact ==="
echo "Package generated at: ${DEB_FILE}"
ls -lh "${DEB_FILE}"
dpkg-deb -I "${DEB_FILE}"
echo "Package contents preview:"
dpkg-deb -c "${DEB_FILE}" | head -n 30 || true

echo "=== Build Complete! ==="
