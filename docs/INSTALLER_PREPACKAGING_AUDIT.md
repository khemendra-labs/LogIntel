# LOGINTEL DESKTOP INSTALLER: PRE-PACKAGING AUDIT
**Document ID:** `docs/INSTALLER_PREPACKAGING_AUDIT.md`  
**Date:** October 21, 2026  
**Auditor:** Senior Software Verification Engineer and Digital Forensics Architect  
**Objective:** Read-only baseline inspection and validation of the Debian package assembly pipeline before building the desktop `.deb` installer.

---

## 1. Repository Baseline & Environment Verification

### 1.1 Repository Root & Git Status
- **Repository Root:** `/home/khemendra-labs/LogIntel`
- **Active Branch:** `master` (synchronized with `origin/master`)
- **HEAD Commit:** `932f3ed` (*"feat: implement multi-host investigation workbench with backend dossier integration and verification audits"*)
- **Working Tree State (`git status --short`):**
  - Modified tracked files (Frontend redesign):
    - `M apps/desktop/index.html` (synchronous theme initialization script)
    - `M apps/desktop/src/App.tsx` (request locking, KPI metrics, drill-down bindings)
    - `M apps/desktop/src/components/Header.tsx` (theme switcher segmented control)
    - `M apps/desktop/src/components/StatusBadge.tsx` (CRITICAL badge distinction)
    - `M apps/desktop/src/features/AttackGraphVisualizer.tsx` (theme CSS variables)
    - `M apps/desktop/src/features/InvestigationMultiHostWorkbench.tsx` (semantic tokens)
    - `M apps/desktop/src/main.tsx` (initTheme call prior to mounting)
    - `M apps/desktop/src/pages/OverviewPage.tsx` (redesigned 4-tier operational overview)
    - `M apps/desktop/src/styles/theme.css` (full light/dark token hierarchy)
  - Untracked files (Newly added modules, tests, and documentation):
    - `?? apps/desktop/src/__tests__/dashboard.test.ts`
    - `?? apps/desktop/src/__tests__/theme.test.ts`
    - `?? apps/desktop/src/components/charts/`
    - `?? apps/desktop/src/lib/theme.ts`
    - `?? docs/FRONTEND_REDESIGN_CORRECTED_PLAN_AND_VERIFICATION.md`
    - `?? docs/FRONTEND_REDESIGN_FINAL_VERIFICATION_REPORT.md`

### 1.2 Toolchain & Host System Resources
- **Rust Toolchain:** `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1 (797e8a9bc 2026-08-05)`
- **Node.js Environment:** `v22.22.1`, `npm 9.2.0`
- **Python Environment:** Python 3.12.3 in virtual environment (`apps/engine/.venv`)
- **System Packaging Tools:** `dpkg-deb`, `strip`, `md5sum` (available)
- **Disk Space Available:** `381 GB` available on `/dev/nvme0n1p2` (15% utilized)
- **Runtime Host Dependencies:**
  - `libwebkit2gtk-4.1-0` (installed and active)
  - `libgtk-3-0` / `libgtk-3-0t64` (installed and active)
  - `python3 (>= 3.10)` (Python 3.12 system runtime present)

---

## 2. Existing Installer Baseline & Preservation

- **Existing Package Path:** `packaging/deb/logintel_0.1.0_amd64.deb`
- **File Size:** `11,961,850 bytes` (11.41 MiB)
- **File Timestamp:** `Sep 30 22:23`
- **SHA-256 Checksum:** `7b00e30a6c056277966643f49ec444c21984f32844eca383d561d941e584ac9a`
- **Preservation Policy:** Strict compliance with preservation directives. The existing baseline installer will **NOT** be deleted or overwritten. The new build will be output to a distinct filename:
  `packaging/deb/logintel_0.1.0_redesign_amd64.deb`.

---

## 3. Tauri & Packaging Architecture Inspection

### 3.1 Tauri Configuration (`apps/desktop/src-tauri/tauri.conf.json`)
- **Product Name:** `logintel`
- **Package Version:** `0.1.0`
- **Identifier:** `com.logintel.app`
- **Build Settings:**
  - `frontendDist`: `../dist`
  - `beforeBuildCommand`: `npm run build`
- **Bundle Targets:** `["deb"]`
- **System Package Dependencies:** `libwebkit2gtk-4.1-0, libgtk-3-0t64 | libgtk-3-0, python3 (>= 3.10)`

### 3.2 Packaging Script (`scripts/build_deb.sh`)
The project maintains a dedicated packaging pipeline that automates the generation of a production-grade Debian installer:
1. Builds frontend assets via `npm run build` in `apps/desktop`.
2. Compiles the native desktop shell via `cargo build --release` in `apps/desktop/src-tauri` using `--remap-path-prefix` to prevent local build path leakage.
3. Stages the standard Debian directory hierarchy under `build/deb/`.
4. Installs the stripped binary to `/usr/bin/logintel-bin`.
5. Deploys the Python engine source and sanitized runtime virtual environment to `/usr/lib/logintel/engine/`.
6. Installs canonical detection rules to `/usr/share/logintel/rules/` and `/usr/lib/logintel/engine/rules/`.
7. Installs `/usr/bin/logintel` desktop launcher, `/usr/bin/logintel-engine` CLI, and `/usr/bin/logintel-replay` CLI.
8. Deploys desktop entry `/usr/share/applications/logintel.desktop` and hicolor application icons.
9. Generates Debian control files (`DEBIAN/control`, `DEBIAN/md5sums`, `DEBIAN/postinst`, `DEBIAN/prerm`, `DEBIAN/postrm`).
10. Compiles the `.deb` package via `dpkg-deb --build --root-owner-group`.

---

## 4. Runtime Lifecycle & Environment Independence

### 4.1 Backend Engine Discovery & Spawning
Inspection of `apps/desktop/src-tauri/src/lib.rs` confirms that the packaged application does not depend on development paths or an active IDE:
- **Port Handshake:** The native desktop shell tests `127.0.0.1:41721` via `verify_engine_handshake()` querying `/api/v1/handshake`. If the engine is already active, it attaches seamlessly.
- **Process Spawning Candidates:** If port 41721 is unassigned, `spawn_engine_process()` prioritizes packaged paths:
  1. `/usr/lib/logintel/engine/.venv/bin/python` (Packaged isolated venv)
  2. `/usr/lib/logintel/engine/venv/bin/python`
  3. `./apps/engine/.venv/bin/python` (Local development fallback)
  4. `/usr/bin/python3` (System fallback)
- **Source Resolution:** Sets `PYTHONPATH` to `/usr/lib/logintel/engine` and `LOGINTEL_RULES_DIR` to `/usr/share/logintel/rules`.
- **Termination & Monitoring:** Dedicated thread monitors process health; graceful SIGTERM is issued upon Tauri window closure.

### 4.2 Data Storage & User State Preservation
Inspection of `apps/engine/src/logintel/config/settings.py` confirms that user data is isolated from the software installation:
- **Data Directory:** Follows the XDG Base Directory specification: `$XDG_DATA_HOME/logintel` or `~/.local/share/logintel/` (permissions enforced at `0700`).
- **Telemetry Database (`logintel.db`):** Stored in user data directory; never placed in `/usr/` or ephemeral development caches.
- **Analyst Cases Database (`cases.db`):** Stored in user data directory.
- **Engine Authentication Token (`.engine_token`):** Stored in user data directory (`0600` permissions).
- **Uninstall / Upgrade Behavior:** `DEBIAN/postrm` guarantees that user telemetry and case databases in `~/.local/share/logintel/` are preserved during package removal or upgrade.

---

## 5. Pre-Packaging Blockers & Risk Assessment

- **Blockers:** Zero blockers. All required compilation tools (`cargo`, `rustc`, `node`, `npm`, `dpkg-deb`) are present and operational.
- **Identified Risk:** `scripts/build_deb.sh` hardcodes `DEB_FILE="${OUTPUT_DIR}/${PACKAGE_NAME}_${VERSION}_amd64.deb"`. Executing the script as-is would overwrite the existing baseline installer.
- **Safe Resolution:** Parameterize `DEB_FILE="${DEB_FILE:-${OUTPUT_DIR}/${PACKAGE_NAME}_${VERSION}_amd64.deb}"` in `scripts/build_deb.sh` so that passing `DEB_FILE=...` creates a distinct installer file (`logintel_0.1.0_redesign_amd64.deb`), preserving the baseline file intact.

---

## 6. Audit Verdict

**Pre-Packaging Audit Result:** **PASSED**.  
The project possesses a proven, self-contained Debian packaging pipeline. The proposed build path is safe, non-destructive, and verified for execution.
