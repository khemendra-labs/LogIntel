# LogIntel — Development Guide

## Prerequisites

- **OS**: Ubuntu 22.04+ / 24.04+ (or Debian-based distribution)
- **User Groups**: Member of `adm` or `systemd-journal` to read system telemetry (`sudo usermod -aG adm $USER`).
- **Python**: 3.11+
- **Node.js**: 18+ and npm
- **Rust & Cargo**: 1.77+
- **System Libraries**: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`

## Local Development Workflow

### 1. Engine Setup
```bash
# Setup Python virtualenv and install dependencies
cd apps/engine
python3 -m venv --without-pip .venv
curl -sS https://bootstrap.pypa.io/get-pip.py | .venv/bin/python3
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .

# Run test suite
PYTHONPATH=. .venv/bin/pytest tests/

# Run analysis engine locally
.venv/bin/python -m logintel.main --host 127.0.0.1 --port 41721
```

### 2. Desktop Frontend Setup
```bash
cd apps/desktop
npm install

# Run frontend in development mode
npm run dev

# Run Tauri desktop app with hot reload
npm run tauri dev
```

### 3. Verify Local API Endpoints
```bash
# System status
curl -s http://127.0.0.1:41721/api/v1/system/status | jq .

# Telemetry health
curl -s http://127.0.0.1:41721/api/v1/telemetry/health | jq .

# Query recent events
curl -s "http://127.0.0.1:41721/api/v1/events?limit=5" | jq .
```
