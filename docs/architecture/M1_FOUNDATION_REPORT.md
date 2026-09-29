# LogIntel — M1 Foundation Architecture & Audit Report

## 1. Environment Audit
- **Operating System**: Ubuntu 24.04.5 LTS (Noble Numbat), Linux kernel `7.0.0-34-generic` x86_64
- **Current User**: `khemendra-labs` (UID: 1000, GID: 1000)
- **User Groups**: Member of `adm`, `sudo`, `users`
- **Linux Security Telemetry Permissions**:
  - `/var/log/auth.log` (`-rw-r----- 1 syslog adm`): Direct read access verified via `adm` group membership.
  - `/var/log/syslog` (`-rw-r----- 1 syslog adm`): Direct read access verified via `adm` group membership.
  - `/var/log/kern.log` (`-rw-r----- 1 syslog adm`): Direct read access verified via `adm` group membership.
  - `journalctl` (systemd journal): Direct unprivileged query access verified.
- **Python**: 3.12.3 installed (PEP 668 managed). Standalone virtual environment with bootstrapped pip configured at `apps/engine/.venv`.
- **Node.js**: v18.19.1, npm 9.2.0.
- **Rust Toolchain**: rustc 1.98.1, cargo 1.98.1.
- **System Libraries**: `libwebkit2gtk-4.1-dev` and `libgtk-3-dev` installed.
- **SQLite**: SQLite 3.45.1 built-in.

---

## 2. Repository Audit
- Fresh repository initialized at `/home/khemendra-labs/LogIntel`.
- Complete layered architecture established:
  - `apps/desktop`: Tauri v2 + React 18 + TypeScript + Vite.
  - `apps/engine`: Python 3.12 analysis and telemetry engine.
  - `packaging/deb` & `scripts/build_deb.sh`: Debian package builder.
  - `docs/`: Architecture, canonical schema, development, and packaging manuals.

---

## 3. Architecture Recommendation
- **Layer Separation**: The React/Tauri frontend is strictly decoupled from domain security analysis. The frontend communicates with the engine via a local REST API (`127.0.0.1:41721`).
- **Telemetry Ingestion Pipeline**:
  `Collectors (Journal, Auth, Syslog, Kern)` → `RawRecord` → `ParserRegistry (SSH, Sudo, PAM, UserMgmt, Kernel)` → `Normalization & Sanitization (ANSI strip, length cap, IOC extraction)` → `SQLite Event Repository (WAL mode)` → `Local REST API` → `Tauri UI`.
- **Privilege Model**: Non-root operation utilizing standard Linux `adm` group permissions. Inability to access protected telemetry produces actionable user guidance rather than silent failure or requiring `sudo`.

---

## 4. Dependency Plan
- **Python Engine**:
  - `pydantic`: High-performance typed domain models and serialization.
  - `fastapi` & `uvicorn`: Lightweight local ASGI server.
  - `pytest`, `pytest-asyncio`, `httpx`: Automated testing suite.
- **Desktop Frontend**:
  - `react` & `react-dom` 18: User interface.
  - `vite`: Fast ESM build tooling.
  - `typescript`: Type safety across API responses and components.
  - `@tauri-apps/api` & `@tauri-apps/cli` 2.x: Desktop window management.

---

## 5. Implementation Status & Verification
- [x] **Canonical Event Schema**: Complete domain model with Actor, Process, Network, IOCs, and immutable raw records.
- [x] **Linux Collectors**: Live verified for `journald`, `/var/log/auth.log`, `/var/log/syslog`, and `/var/log/kern.log`.
- [x] **Parser Framework**: 9 deterministic tests passing for SSH login failures/successes, sudo execution, PAM session open/close, user administration, and kernel alerts.
- [x] **Persistence & Restart**: SQLite WAL store verified with compound indexes; verified events survive complete engine restart.
- [x] **REST API / IPC**: Endpoints tested for status, telemetry health, paginated events, event details, and aggregations.
- [x] **Enterprise UI**: Restrained technical palette (IBM Plex typography, warm neutral surfaces, dark charcoal text, custom SVG icons, NO AI template gimmicks).
- [x] **Packaging**: Debian package generation script (`scripts/build_deb.sh`).

---

## 6. Risks & Mitigation
- **Log Rotation**: Handled by `FileTailer` using inode detection and size shrinkage detection.
- **Hostile Input Injection**: Mitigated through ANSI stripping, 16KB length bounding, and 100% parameterized SQL.
- **Telemetry Volume**: Mitigated via pagination, batch ingestion, and database indexes on timestamp, host, type, user, IP, and outcome.
