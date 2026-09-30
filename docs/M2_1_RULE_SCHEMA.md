# LogIntel — Detection Rule Specification & Schema (M2.1)

## 1. Overview

LogIntel M2 introduces a deterministic, local-first detection engine for Linux telemetry. Detection rules in LogIntel are **pure declarative data specifications** (YAML or JSON) validated against strict Pydantic schemas. 

To maintain system integrity and prevent arbitrary code execution:
- Rules are **never** executable code (zero `eval`, `exec`, shell scripts, or dynamic imports).
- Rules can only reference explicitly registered canonical event fields.
- Regular expressions are bounded in length and pre-compiled during validation.
- All rule inputs are strictly bounded to prevent Denial of Service (DoS) or memory exhaustion.

---

## 2. Rule Structure

Every detection rule file represents a mapping conforming to the following schema:

```yaml
id: <rule_id>                  # Required: string, e.g. "auth.ssh_bruteforce"
name: <rule_name>              # Required: string (1..128 chars)
description: <description>     # Required: string (1..1024 chars)
severity: <severity>          # Required: INFORMATIONAL | NOTICE | WARNING | ALERT | CRITICAL
category: <category>          # Required: AUTH | PRIVILEGE | PROCESS | NETWORK | ACCOUNT | SECURITY
rule_type: <rule_type>        # Required: ATOMIC | THRESHOLD
enabled: <boolean>             # Optional: true | false (default: true)

conditions:                    # Required: conditions block
  all:                         # Optional: list of conditions (conjunction: AND)
    - field: <field_name>
      operator: <operator>
      value: <value>
  any:                         # Optional: list of conditions (disjunction: OR)
    - field: <field_name>
      operator: <operator>
      value: <value>

# Required ONLY for THRESHOLD rules (Forbidden for ATOMIC rules):
threshold:
  count: <positive_integer>    # 1..1,000,000
  window_seconds: <integer>    # 1..86,400 (up to 24 hours)

# Required ONLY for THRESHOLD rules (Forbidden for ATOMIC rules):
group_by:
  - <canonical_field_1>
  - <canonical_field_2>

# Optional for all rules:
cooldown_seconds: <integer>    # 1..604,800 (up to 7 days)
```

---

## 3. Schema Attributes & Validation Rules

### 3.1 Rule ID (`id`)
- **Format**: Lowercase alphanumerics and underscores, segmented by periods: `^[a-z0-9_]+(\.[a-z0-9_]+)+$`.
- **Length**: 3 to 64 characters.
- **Security Constraints**: Path traversal sequences (`..`), slashes (`/`, `\`), whitespace, and control characters are strictly rejected.
- **Uniqueness**: Rule IDs must be unique across the entire rule registry; duplicate rule registrations are rejected with `DuplicateRuleError`.

### 3.2 Severity (`severity`)
Must match a valid member of LogIntel's canonical `Severity` enumeration:
- `DEBUG`
- `INFORMATIONAL`
- `NOTICE`
- `WARNING`
- `ALERT`
- `CRITICAL`

### 3.3 Category (`category`)
Closed enumeration categorizing the domain of telemetry:
- `AUTH`: Authentication and session management.
- `PRIVILEGE`: Sudo execution, capability transitions, and privilege elevation.
- `PROCESS`: Executable launches, suspicious interpreters, command line arguments.
- `NETWORK`: Inbound/outbound connections, ports, and protocols.
- `ACCOUNT`: User and group mutations (`useradd`, `usermod`, `groupadd`).
- `SECURITY`: Security subsystems (AppArmor, SELinux, auditd denials).

### 3.4 Rule Type (`rule_type`)
- `ATOMIC`: Single-event match. Fires immediately when an event satisfies the condition predicates.
  - *Constraint*: Must NOT contain `threshold` or `group_by`.
- `THRESHOLD`: Multi-event aggregation. Requires a defined event frequency within a temporal sliding window.
  - *Constraint*: MUST contain valid `threshold` (`count > 0`, `window_seconds > 0`) and non-empty `group_by` list.

---

## 4. Condition Model & Operators

A rule must define at least one condition under `conditions.all` or `conditions.any`. The total condition count across a rule is capped at 32.

### 4.1 Supported Operators
| Operator | Description | Expected Value |
|---|---|---|
| `equals` | Exact scalar equality | String, Integer, or Enum Literal |
| `not_equals` | Scalar inequality | String, Integer, or Enum Literal |
| `in` | Membership in set | Non-empty list of literals (max 100) |
| `not_in` | Non-membership in set | Non-empty list of literals (max 100) |
| `starts_with` | String prefix match | String |
| `ends_with` | String suffix match | String |
| `contains` | Substring match | String |
| `regex` | Regular expression match | Valid string pattern (max 256 chars) |
| `exists` | Field presence check | Boolean (`true`/`false`) or omitted |

---

## 5. Canonical Field Registry

Conditions and `group_by` clauses may only reference recognized canonical event fields:

| Field Name | Type | Description |
|---|---|---|
| `event_type` | `ENUM_EVENT_TYPE` | Canonical `EventType` enum |
| `severity` | `ENUM_SEVERITY` | Canonical `Severity` enum |
| `outcome` | `ENUM_OUTCOME` | Canonical `Outcome` enum (`SUCCESS`, `FAILURE`, `ATTEMPT`, `UNKNOWN`) |
| `action` | `STRING` | Action name (`LOGIN`, `COMMAND`, `CREATE`, etc.) |
| `host` | `STRING` | Hostname / FQDN |
| `source` | `STRING` | Log source (`auth.log`, `journald`, `kern.log`, `syslog`) |
| `username` | `STRING` | Normalized actor username |
| `uid` | `INTEGER` | User ID (>= 0) |
| `session_id` | `STRING` | Audit / PAM session identifier |
| `terminal` | `STRING` | TTY / PTS terminal identifier |
| `process_name` | `STRING` | Short binary name (`bash`, `curl`) |
| `process_pid` | `INTEGER` | Process ID (>= 0) |
| `process_ppid` | `INTEGER` | Parent Process ID (>= 0) |
| `process_executable` | `STRING` | Absolute path to executable |
| `process_command_line` | `STRING` | Full CLI command arguments |
| `src_ip` | `STRING` | Source IP address (IPv4 / IPv6) |
| `src_port` | `INTEGER` | Source port (0..65535) |
| `dst_ip` | `STRING` | Destination IP address |
| `dst_port` | `INTEGER` | Destination port (0..65535) |
| `protocol` | `STRING` | Network protocol (`tcp`, `udp`, etc.) |
| `summary` | `STRING` | Normalized event summary string |
| `raw_message` | `STRING` | Original unaltered raw message |
| `parser` | `STRING` | Responsible parser identifier |
| `source_file` | `STRING` | Path to log file |
| `source_offset` | `STRING` | Offset in source file |
| `iocs` | `LIST_STRING` | Extracted indicators of compromise |
| `metadata.<subfield>` | `METADATA_VALUE` | Safe nested key in parser metadata dict |

### 5.1 Field Aliases & Normalization
For author ergonomics, aliases are automatically normalized to canonical names:
- `source_ip` ➔ `src_ip`
- `dest_ip`, `destination_ip` ➔ `dst_ip`
- `source_port` ➔ `src_port`
- `dest_port`, `destination_port` ➔ `dst_port`
- `user` ➔ `username`
- `executable` ➔ `process_executable`
- `command`, `cmdline` ➔ `process_command_line`
- `pid`, `ppid` ➔ `process_pid`, `process_ppid`
- Model-qualified names (`actor.username`, `process.executable`, `network.src_ip`) ➔ normalized canonical names

### 5.2 Nested Metadata Fields
Nested fields under `metadata.` are strictly validated:
- Must match `^[a-zA-Z0-9_]{1,64}$`.
- Python dunder attributes (`__class__`, `__dict__`, `__globals__`, etc.) and builtins are strictly rejected.

---

## 6. Security Guarantees

1. **Safe YAML Parsing**: Parsing strictly utilizes `yaml.safe_load()`. Unsafe Python object constructors (`!!python/object/...`) are blocked.
2. **Deterministic Validation**: Malformed syntax, unknown fields, type mismatches, and invalid regexes trigger immediate, clear errors with field suggestions.
3. **No Code Execution**: Rules do not contain or evaluate Python code, shell commands, or expressions.
4. **ReDoS Mitigation**: Regex patterns are capped at 256 characters and compiled during schema validation.

---

## 7. Examples

### 7.1 Atomic Rule Example: AppArmor Denial
```yaml
id: security.apparmor_denial
name: AppArmor Access Denial
description: Detect AppArmor access denial events
severity: ALERT
category: SECURITY
rule_type: ATOMIC
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: SECURITY_ACCESS_DENIED
    - field: outcome
      operator: equals
      value: FAILURE
```

### 7.2 Threshold Rule Example: SSH Brute Force
```yaml
id: auth.ssh_bruteforce
name: SSH Brute Force
description: Detect repeated SSH authentication failures
severity: ALERT
category: AUTH
rule_type: THRESHOLD
enabled: true

conditions:
  all:
    - field: event_type
      operator: equals
      value: AUTH_LOGIN_FAILURE
    - field: outcome
      operator: equals
      value: FAILURE

threshold:
  count: 5
  window_seconds: 300

group_by:
  - src_ip
  - host

cooldown_seconds: 3600
```
