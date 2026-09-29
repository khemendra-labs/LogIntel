# LogIntel — System Architecture & Design

LogIntel is a GUI-first, local-first Linux security telemetry and investigation platform distributed as an installable `.deb` package.

## 1. High-Level Pipeline

LogIntel transforms noisy Linux system telemetry into structured, searchable, evidence-backed security investigations without sending data outside the local machine.

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

## 2. Component Separation

### Desktop Shell & Presentation Layer (`apps/desktop`)
- **Framework**: Tauri v2 + React 18 + TypeScript + Vite.
- **Role**: Render technical investigation interfaces (`Overview` and `Activity`), allow multidimensional filtering, and display complete raw provenance.
- **Rule**: The GUI never contains security detection logic. It communicates strictly with the local Python engine through HTTP/REST queries.

### Analysis & Telemetry Engine (`apps/engine`)
- **Package**: `logintel` (Python 3.12).
- **Subsystems**:
  - `collectors`: Abstracted input ingestion modules for systemd journal, auth.log, syslog, and kern.log.
  - `parsers`: Structured log decoders mapping raw syntax to security semantics.
  - `normalization`: ANSI escape stripping, message length enforcement, IPv4/IPv6 validation, and IOC extraction.
  - `storage`: SQLite connection management, migrations runner, and indexed repository queries.
  - `health`: Source existence, read permissions, file metrics, and diagnostic repair hints.
  - `api`: FastAPI application exposing `/api/v1` routes with automated engine lifecycle hooks.

### Local Storage (`SQLite`)
- Located in `$XDG_DATA_HOME/logintel/logintel.db` (typically `~/.local/share/logintel/logintel.db`).
- Configured with `PRAGMA journal_mode = WAL;` and `PRAGMA synchronous = NORMAL;`.
- Tables: `events`, `hosts`, `sources`, `ingestion_state`, `schema_migrations`.

## 3. Privilege & Security Model

1. **Non-Root Execution**: The desktop application and analysis engine run as a standard non-root user.
2. **Linux Group Security**: On Debian/Ubuntu systems, telemetry files (`/var/log/auth.log`, `/var/log/syslog`, `/var/log/kern.log`) and journald access are granted to members of the `adm` or `systemd-journal` groups. Users belonging to `adm` can read these files directly without requiring `sudo` or elevated root privileges.
3. **Graceful Permission Failures**: If permission is denied, the application does not crash. It marks the source as `UNAVAILABLE` in the Telemetry Health panel and gives the exact Linux remediation command: `sudo usermod -aG adm $USER`.
4. **Hostile Input Hardening**:
   - Strips ANSI escape sequences and control characters.
   - Enforces a 16KB per-message truncation limit to prevent memory exhaustion.
   - Uses parameterized SQL queries exclusively (never string formatting or concatenation).
   - Validates IP addresses with Python's standard `ipaddress` library before indexing.
