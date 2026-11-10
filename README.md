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

## Professional Operations Controls

LogIntel remains local-first by default. The following optional controls are
intended for managed Linux environments and are disabled until an operator
configures them:

- **Fleet intake:** `POST /api/v1/fleet/ingest` accepts bounded raw telemetry
  batches from remote Linux collectors only when `remote_ingest.enabled` is set
  and `LOGINTEL_AGENT_TOKEN` supplies a separate agent token. It is independent
  of the desktop IPC token.
- **Retention:** retention is dry-run by default and only deletes old events
  that are not linked as detection evidence. Set `retention.enabled` before
  calling `POST /api/v1/system/maintenance/retention` with `dry_run: false`.
- **Notifications:** set `LOGINTEL_NOTIFICATIONS_ENABLED=true` for a bounded
  local notification log sink. A webhook is opt-in via
  `LOGINTEL_NOTIFICATION_SINK=webhook` and
  `LOGINTEL_NOTIFICATION_WEBHOOK_URL`; HTTPS is required for non-local hosts.

No remote listener, data deletion, or outbound notification is enabled by the
default installation.

### Remote Linux Agent

The engine package includes a small `logintel-agent` CLI for environments where
telemetry must cross hosts. Enrollment writes an owner-only configuration and
supports a private CA plus an optional client certificate/key for mTLS:

```bash
logintel-agent --config /etc/logintel-agent/config.json enroll \
  --endpoint https://logintel.example.internal \
  --token "$LOGINTEL_AGENT_TOKEN" \
  --ca-file /etc/logintel-agent/ca.pem \
  --client-cert-file /etc/logintel-agent/agent.pem \
  --client-key-file /etc/logintel-agent/agent-key.pem
```

Feed normalized raw-record JSONL into `logintel-agent queue`, then invoke
`logintel-agent flush` from a systemd timer or a lightweight collector loop.
The agent writes batches to a 0700 disk spool before upload, uses a 64 MiB
default capacity, and preserves a batch for retry if the connection fails.

For unattended collection, `logintel-agent run` tails appended auth, syslog,
kernel, and audit log lines, tracks file inode/offsets across rotation, and
collects a bounded journald batch each cycle. The Debian package includes a
disabled-by-default `logintel-agent.service`; after secure enrollment, enable
it with `sudo systemctl enable --now logintel-agent`.

---

## Documentation

- [Architecture Design](docs/architecture/ARCHITECTURE.md)
- [Canonical Event Schema](docs/schemas/CANONICAL_SCHEMA.md)
- [Development Setup](docs/development/DEVELOPMENT.md)
- [Debian Packaging](docs/deployment/PACKAGING.md)

---

## License

Internal Enterprise / Proprietary. All rights reserved.
