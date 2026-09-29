# LogIntel — Canonical Security Event Schema

LogIntel normalizes diverse Linux log records into a typed canonical representation while preserving immutable raw records and parser provenance.

## 1. Schema Definition

| Field | Type | Nullable | Description |
| :--- | :--- | :---: | :--- |
| `id` | String (UUIDv4) | No | Unique canonical event identifier |
| `timestamp` | Timestamp (ISO 8601 UTC) | No | Original event timestamp from log |
| `ingested_at` | Timestamp (ISO 8601 UTC) | No | Timestamp when engine processed record |
| `host` | String | No | Hostname of the originating node |
| `source` | String | No | Telemetry source identifier (`journald`, `auth.log`, `syslog`, `kern.log`) |
| `event_type` | Enum | No | Normalized event classification |
| `severity` | Enum | No | Event severity tier |
| `actor.username` | String | Yes | Username associated with the activity |
| `actor.uid` | Integer | Yes | User ID |
| `actor.session_id` | String | Yes | Session ID (e.g. systemd or PAM session) |
| `actor.terminal` | String | Yes | TTY or PTS device if applicable |
| `process.name` | String | Yes | Process or daemon name (e.g. `sshd`, `sudo`) |
| `process.pid` | Integer | Yes | Process ID |
| `process.ppid` | Integer | Yes | Parent process ID |
| `process.executable` | String | Yes | Path to binary executable |
| `process.command_line`| String | Yes | Executed command line string |
| `network.src_ip` | String | Yes | Validated source IPv4/IPv6 address |
| `network.src_port` | Integer | Yes | Source port |
| `network.dst_ip` | String | Yes | Validated destination IPv4/IPv6 address |
| `network.dst_port` | Integer | Yes | Destination port |
| `network.protocol` | String | Yes | Protocol (`tcp`, `udp`, `icmp`) |
| `action` | String | Yes | High-level action (e.g. `ssh_authenticate`, `sudo_command`) |
| `outcome` | Enum | No | `SUCCESS`, `FAILURE`, `ATTEMPT`, `UNKNOWN` |
| `summary` | String | No | Analyst-readable single-line explanation |
| `raw_message` | String | No | Sanitized, complete original raw telemetry line |
| `iocs` | Array of Strings | No | Extracted indicators (IPs, hashes, etc.) |
| `parser` | String | No | Provenance identifier of the parser that decoded the record |
| `source_file` | String | Yes | File path or source stream |
| `source_offset` | String | Yes | Cursor ID or byte offset for provenance tracing |
| `metadata` | JSON Object | No | Parser-specific supplementary attributes |

## 2. Event Types & Severity Tiers

### Severity Tiers
- `CRITICAL`: System failure, unauthorized root command, kernel panic
- `ALERT`: Authentication failure, privilege escalation failure, crash
- `WARNING`: Blocked firewall traffic, invalid user attempts
- `NOTICE`: Successful login, privilege elevation command, account creation
- `INFORMATIONAL`: General session open/close, service state changes
- `DEBUG`: Verbose telemetry diagnostics

### Event Types
- `AUTH_LOGIN_SUCCESS`, `AUTH_LOGIN_FAILURE`, `AUTH_LOGOUT`
- `SESSION_OPEN`, `SESSION_CLOSE`
- `PRIVILEGE_ELEVATION_ATTEMPT`, `PRIVILEGE_ELEVATION_SUCCESS`, `PRIVILEGE_ELEVATION_FAILURE`, `SUDO_COMMAND`
- `USER_CREATE`, `USER_DELETE`, `USER_MODIFY`, `GROUP_MODIFY`
- `SYSTEM_BOOT`, `SYSTEM_SHUTDOWN`, `KERNEL_MESSAGE`, `SYSTEM_SERVICE_STATE`
- `SYSTEM_GENERIC`, `UNKNOWN`
