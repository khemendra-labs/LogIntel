# LogIntel

> **Linux Security Telemetry & Investigation Platform**

LogIntel is a GUI-first, local-first Linux security telemetry and investigation application. It ingests raw telemetry from `journald`, `/var/log/auth.log`, `/var/log/syslog`, and `/var/log/kern.log`, normalizes it into a canonical security event representation, indexes it in SQLite, and provides an analyst-centric desktop interface for evidence-backed investigations.

LogIntel operates completely locally on your system. Telemetry never leaves the host.

---

## Architecture Overview

```text
RAW LINUX TELEMETRY
  (journald, auth.log, syslog, kern.log)
        ↓
   COLLECTION
  (FileTailer, JournalCollector with cursor/offset tracking)
        ↓
    PARSING
  (Extensible ParserRegistry: OpenSSH, Sudo, PAM, UserMgmt, Kernel)
        ↓
  NORMALIZATION
  (Sanitization, ANSI strip, IOC extraction, CanonicalEvent mapping)
        ↓
   PERSISTENCE
  (SQLite WAL Mode, compound indices on timestamp, type, user, IP)
        ↓
 LOCAL REST / IPC API
  (FastAPI on 127.0.0.1:41721 with CORS restriction)
        ↓
TAURI DESKTOP GUI
  (React + TypeScript, restrained enterprise visual design)
```

---

## Core Capabilities (M1 Foundation)

- **Telemetry Ingestion**: Ingests historical and live telemetry from:
  - Systemd Journal (`journald`) via JSON cursor tracking
  - `/var/log/auth.log` (Authentication and authorization events)
  - `/var/log/syslog` (System daemon activity)
  - `/var/log/kern.log` (Kernel diagnostics, firewall drops, segmentation faults)
- **Parser Framework**:
  - OpenSSH authentication (failures, successes, invalid user attempts)
  - Sudo command execution and privilege elevation failures
  - PAM session lifecycle (open, close, authentication failures)
  - User and group account administration (`useradd`, `userdel`, `groupadd`)
  - Linux kernel events (UFW firewall drops, segfaults, system boot)
  - Generic Syslog fallback with RFC 5424 and RFC 3164 support
- **Canonical Security Schema**: Typed domain model tracking Actor (`username`, `uid`), Process (`name`, `pid`, `command_line`), Network (`src_ip`, `dst_ip`, `port`), Outcome, IOCs, and provenance.
- **Fast Local Storage**: SQLite with Write-Ahead Logging (WAL) and performance indexes on time, host, type, user, IP, and outcome.
- **Telemetry Health Diagnostics**: Real-time audit of source files, journald accessibility, read permissions, and actionable Linux group remediation hints.
- **Desktop UI**:
  - **Overview**: Ingestion counters, events by source, severity breakdown, top event types, and recent security alerts.
  - **Activity**: Technical investigation table with multi-dimensional filtering (source, severity, user, IP, outcome, full-text search) and pagination.
  - **Event Detail**: Deep inspection modal showing normalized attributes, extracted IOCs, and immutable raw log evidence.
- **Security & Privilege Model**: Runs as an unprivileged normal user by leveraging standard Linux `adm` / `systemd-journal` group read access.

---

## Quickstart & Local Development

### 1. Requirements
- Ubuntu 22.04+ or 24.04+
- Python 3.11+
- Node.js 18+ and npm
- Rust & Cargo 1.77+
- Member of `adm` group (`sudo usermod -aG adm $USER`)

### 2. Backend Engine
```bash
# Setup Python environment
cd apps/engine
python3 -m venv --without-pip .venv
curl -sS https://bootstrap.pypa.io/get-pip.py | .venv/bin/python3
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .

# Run test suite
PYTHONPATH=. .venv/bin/pytest tests/

# Launch engine
.venv/bin/python -m logintel.main
```

### 3. Frontend & Desktop App
```bash
cd apps/desktop
npm install
npm run build

# Launch Tauri desktop application
npm run tauri dev
```

---

## Packaging

LogIntel is packaged as a standard Debian package (`.deb`):

```bash
./scripts/build_deb.sh
```

Install:
```bash
sudo dpkg -i packaging/deb/logintel_0.1.0_amd64.deb
```

Run:
```bash
logintel
```

---

## Documentation

- [Architecture Design](docs/architecture/ARCHITECTURE.md)
- [Canonical Event Schema](docs/schemas/CANONICAL_SCHEMA.md)
- [Development Setup](docs/development/DEVELOPMENT.md)
- [Debian Packaging](docs/deployment/PACKAGING.md)

---

## License

Internal Enterprise / Proprietary. All rights reserved.
