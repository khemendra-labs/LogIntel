#!/usr/bin/env bash
set -euo pipefail

# LogIntel Debian Package Builder (M2.11 Production Release)
# Builds the frontend, compiles the Tauri shell, packages the self-contained
# Python engine and canonical detection rules, and generates a standalone .deb
# installer using standard Debian packaging.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="0.1.0"
PACKAGE_NAME="logintel"
DEB_DIR="${ROOT_DIR}/build/deb"
OUTPUT_DIR="${ROOT_DIR}/packaging/deb"
DEB_FILE="${OUTPUT_DIR}/${PACKAGE_NAME}_${VERSION}_amd64.deb"

echo "=== [1/6] Building Desktop Frontend (Vite + TypeScript) ==="
cd "${ROOT_DIR}/apps/desktop"
npm run build

echo "=== [2/6] Compiling Tauri Desktop Binary (Cargo Release) ==="
cd "${ROOT_DIR}/apps/desktop/src-tauri"
RUSTFLAGS="--remap-path-prefix=${ROOT_DIR}=/build --remap-path-prefix=${HOME}=/home_prefix" cargo build --release

echo "=== [3/6] Staging Debian Package Structure ==="
rm -rf "${DEB_DIR}"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/bin"
mkdir -p "${DEB_DIR}/usr/lib/logintel/engine"
mkdir -p "${DEB_DIR}/usr/share/logintel/rules"
mkdir -p "${DEB_DIR}/usr/share/applications"
mkdir -p "${DEB_DIR}/usr/share/icons/hicolor/128x128/apps"
mkdir -p "${DEB_DIR}/usr/share/icons/hicolor/32x32/apps"
mkdir -p "${DEB_DIR}/usr/share/doc/logintel"
mkdir -p "${DEB_DIR}/usr/lib/systemd/system"
mkdir -p "${OUTPUT_DIR}"

# 1. Install desktop binary and strip release debug symbols
if [ -f "${ROOT_DIR}/apps/desktop/src-tauri/target/release/logintel" ]; then
    cp "${ROOT_DIR}/apps/desktop/src-tauri/target/release/logintel" "${DEB_DIR}/usr/bin/logintel-bin"
elif [ -f "${ROOT_DIR}/apps/desktop/src-tauri/target/release/app" ]; then
    cp "${ROOT_DIR}/apps/desktop/src-tauri/target/release/app" "${DEB_DIR}/usr/bin/logintel-bin"
else
    echo "ERROR: Could not find compiled desktop binary in target/release!" >&2
    exit 1
fi
strip --strip-all "${DEB_DIR}/usr/bin/logintel-bin" 2>/dev/null || true
chmod 755 "${DEB_DIR}/usr/bin/logintel-bin"

# 2. Install Canonical Detection Rules to both /usr/share/logintel/rules and /usr/lib/logintel/engine/rules
cp -r "${ROOT_DIR}/rules/"* "${DEB_DIR}/usr/share/logintel/rules/"
mkdir -p "${DEB_DIR}/usr/lib/logintel/engine/rules"
cp -r "${ROOT_DIR}/rules/"* "${DEB_DIR}/usr/lib/logintel/engine/rules/"
find "${DEB_DIR}/usr/share/logintel/rules" -type d -exec chmod 755 {} +
find "${DEB_DIR}/usr/share/logintel/rules" -type f -exec chmod 644 {} +
find "${DEB_DIR}/usr/lib/logintel/engine/rules" -type d -exec chmod 755 {} +
find "${DEB_DIR}/usr/lib/logintel/engine/rules" -type f -exec chmod 644 {} +

# 3. Install Python engine source and self-contained runtime environment
cp -r "${ROOT_DIR}/apps/engine/src/logintel" "${DEB_DIR}/usr/lib/logintel/engine/"
cp "${ROOT_DIR}/apps/engine/requirements.txt" "${DEB_DIR}/usr/lib/logintel/engine/"
cp "${ROOT_DIR}/apps/engine/pyproject.toml" "${DEB_DIR}/usr/lib/logintel/engine/"

echo "Packaging and sanitizing self-contained Python runtime environment..."
cp -r "${ROOT_DIR}/apps/engine/.venv" "${DEB_DIR}/usr/lib/logintel/engine/.venv"

# Ensure lib64 is a relative symlink to lib
if [ -d "${DEB_DIR}/usr/lib/logintel/engine/.venv/lib64" ] && [ ! -L "${DEB_DIR}/usr/lib/logintel/engine/.venv/lib64" ]; then
    rm -rf "${DEB_DIR}/usr/lib/logintel/engine/.venv/lib64"
    ln -sf lib "${DEB_DIR}/usr/lib/logintel/engine/.venv/lib64"
fi

# Ensure the venv python binaries point to standard system python3
rm -f "${DEB_DIR}/usr/lib/logintel/engine/.venv/bin/python" "${DEB_DIR}/usr/lib/logintel/engine/.venv/bin/python3"
ln -sf /usr/bin/python3 "${DEB_DIR}/usr/lib/logintel/engine/.venv/bin/python"
ln -sf /usr/bin/python3 "${DEB_DIR}/usr/lib/logintel/engine/.venv/bin/python3"

# Sanitize pyvenv.cfg
cat << 'EOF' > "${DEB_DIR}/usr/lib/logintel/engine/.venv/pyvenv.cfg"
home = /usr/bin
include-system-site-packages = false
version = 3.12.3
executable = /usr/bin/python3.12
command = /usr/bin/python3 -m venv /usr/lib/logintel/engine/.venv
EOF

# Sanitize shebangs in .venv/bin/*
for bin_file in "${DEB_DIR}/usr/lib/logintel/engine/.venv/bin/"*; do
    if [ -f "${bin_file}" ] && [ ! -L "${bin_file}" ]; then
        if head -n 1 "${bin_file}" | grep -q "^#\!.*python"; then
            sed -i '1s|^#!.*|#!/usr/lib/logintel/engine/.venv/bin/python3|' "${bin_file}"
        fi
    fi
done

# Sanitize activate scripts
for act in "${DEB_DIR}/usr/lib/logintel/engine/.venv/bin/activate"*; do
    if [ -f "${act}" ]; then
        sed -i 's|/home/[^/]*/LogIntel/apps/engine/\.venv|/usr/lib/logintel/engine/.venv|g' "${act}"
    fi
done

# Clean up development editable links, dist-info development URLs, and caches
find "${DEB_DIR}/usr/lib/logintel/engine/.venv" -name "__editable__*" -delete
find "${DEB_DIR}/usr/lib/logintel/engine/.venv" -name "direct_url.json" -delete
printf "/usr/lib/logintel/engine\n" > "${DEB_DIR}/usr/lib/logintel/engine/.venv/lib/python3.12/site-packages/logintel.pth"

# Clean development caches
find "${DEB_DIR}/usr/lib/logintel/engine" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${DEB_DIR}/usr/lib/logintel/engine" -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
find "${DEB_DIR}/usr/lib/logintel/engine" -type f -exec chmod u=rwX,go=rX {} +
find "${DEB_DIR}/usr/lib/logintel/engine" -type d -exec chmod 755 {} +
find "${DEB_DIR}/usr/lib/logintel/engine/.venv/bin" -type f -exec chmod 755 {} +

# 4. Create wrapper scripts in /usr/bin
# Desktop Application Wrapper
cat << 'EOF' > "${DEB_DIR}/usr/bin/logintel"
#!/usr/bin/env bash
set -e
export PYTHONPATH="/usr/lib/logintel/engine:${PYTHONPATH:-}"
export LOGINTEL_RULES_DIR="/usr/share/logintel/rules"
exec /usr/bin/logintel-bin "$@"
EOF
chmod 755 "${DEB_DIR}/usr/bin/logintel"

# Engine CLI Wrapper
cat << 'EOF' > "${DEB_DIR}/usr/bin/logintel-engine"
#!/usr/bin/env bash
set -e
export PYTHONPATH="/usr/lib/logintel/engine:${PYTHONPATH:-}"
export LOGINTEL_RULES_DIR="/usr/share/logintel/rules"
exec /usr/lib/logintel/engine/.venv/bin/python -m logintel.main "$@"
EOF
chmod 755 "${DEB_DIR}/usr/bin/logintel-engine"

# Historical Replay CLI Wrapper
cat << 'EOF' > "${DEB_DIR}/usr/bin/logintel-replay"
#!/usr/bin/env bash
set -e
export PYTHONPATH="/usr/lib/logintel/engine:${PYTHONPATH:-}"
export LOGINTEL_RULES_DIR="/usr/share/logintel/rules"
exec /usr/lib/logintel/engine/.venv/bin/python -m logintel.detection.replay_cli "$@"
EOF
chmod 755 "${DEB_DIR}/usr/bin/logintel-replay"

# 5. Install Desktop Entry & Icons
cp "${ROOT_DIR}/packaging/deb/logintel.desktop" "${DEB_DIR}/usr/share/applications/logintel.desktop"
chmod 644 "${DEB_DIR}/usr/share/applications/logintel.desktop"
cp "${ROOT_DIR}/apps/desktop/src-tauri/icons/128x128.png" "${DEB_DIR}/usr/share/icons/hicolor/128x128/apps/logintel.png"
chmod 644 "${DEB_DIR}/usr/share/icons/hicolor/128x128/apps/logintel.png"
if [ -f "${ROOT_DIR}/apps/desktop/src-tauri/icons/32x32.png" ]; then
    cp "${ROOT_DIR}/apps/desktop/src-tauri/icons/32x32.png" "${DEB_DIR}/usr/share/icons/hicolor/32x32/apps/logintel.png"
    chmod 644 "${DEB_DIR}/usr/share/icons/hicolor/32x32/apps/logintel.png"
fi

# 6. Install Systemd Service Unit
if [ -f "${ROOT_DIR}/packaging/systemd/logintel-engine.service" ]; then
    cp "${ROOT_DIR}/packaging/systemd/logintel-engine.service" "${DEB_DIR}/usr/lib/systemd/system/logintel-engine.service"
    chmod 644 "${DEB_DIR}/usr/lib/systemd/system/logintel-engine.service"
fi

# 7. Install Documentation and Copyright
cat << 'EOF' > "${DEB_DIR}/usr/share/doc/logintel/copyright"
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: LogIntel
Source: https://github.com/logintel/logintel

Files: *
Copyright: 2026 LogIntel Team
License: Proprietary
EOF
chmod 644 "${DEB_DIR}/usr/share/doc/logintel/copyright"

# 8. Generate DEBIAN/control
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
chmod 644 "${DEB_DIR}/DEBIAN/control"

# 9. Generate DEBIAN/md5sums
(
    cd "${DEB_DIR}"
    find usr -type f -exec md5sum {} + > "${DEB_DIR}/DEBIAN/md5sums"
)
chmod 644 "${DEB_DIR}/DEBIAN/md5sums"

# 10. Generate DEBIAN/postinst
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
    echo " Replay CLI available via:"
    echo "   logintel-replay --help"
    echo "=========================================================="
fi
exit 0
EOF
chmod 755 "${DEB_DIR}/DEBIAN/postinst"

# 11. Generate DEBIAN/prerm
cat << 'EOF' > "${DEB_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e
# Gracefully terminate any lingering user engine processes on uninstall
pkill -f "logintel.main" || true
pkill -f "logintel-bin" || true
exit 0
EOF
chmod 755 "${DEB_DIR}/DEBIAN/prerm"

# 12. Generate DEBIAN/postrm
cat << 'EOF' > "${DEB_DIR}/DEBIAN/postrm"
#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
    fi
fi

if [ "$1" = "purge" ]; then
    echo "Notice: User telemetry databases in ~/.local/share/logintel/ were preserved."
fi
exit 0
EOF
chmod 755 "${DEB_DIR}/DEBIAN/postrm"

echo "=== [4/6] Assembling Debian Package with dpkg-deb ==="
dpkg-deb --build --root-owner-group "${DEB_DIR}" "${DEB_FILE}"

echo "=== [5/6] Verifying Package Artifact and Cleanliness ==="
echo "Package generated at: ${DEB_FILE}"
ls -lh "${DEB_FILE}"
dpkg-deb -I "${DEB_FILE}"

echo "--- Forensic Path Audit for Staging Leakage ---"
LEAK_COUNT=$(find "${DEB_DIR}" -type f -exec grep -l "khemendra-labs" {} + 2>/dev/null | wc -l || true)
if [ "${LEAK_COUNT}" -gt 0 ]; then
    echo "WARNING: Found ${LEAK_COUNT} files containing developer username / repo references:"
    find "${DEB_DIR}" -type f -exec grep -l "khemendra-labs" {} + 2>/dev/null || true
else
    echo "PASS: Zero references to developer username or local repo found in packaged files!"
fi

echo "=== [6/6] Build and Verification Complete! ==="

