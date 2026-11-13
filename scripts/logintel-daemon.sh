#!/usr/bin/env bash
# ==============================================================================
# LogIntel Background Engine Daemon Manager
# Allows the security engine to run continuously 24/7 in the background,
# capturing telemetry and delivering High/Critical Telegram alerts to analysts.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENGINE_DIR="${ROOT_DIR}/apps/engine"
LOGINTEL_HOME="${HOME}/.logintel"
PID_FILE="${LOGINTEL_HOME}/engine.pid"
LOG_FILE="${LOGINTEL_HOME}/engine.log"

mkdir -p "${LOGINTEL_HOME}"

get_pid() {
    if [[ -f "${PID_FILE}" ]]; then
        cat "${PID_FILE}"
    fi
}

is_running() {
    local pid
    pid="$(get_pid)"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

start_daemon() {
    if is_running; then
        echo "[+] LogIntel Engine daemon is ALREADY running (PID: $(get_pid))."
        return 0
    fi

    echo "[*] Starting LogIntel Security Engine daemon in background..."
    cd "${ENGINE_DIR}"

    local python_bin="${ENGINE_DIR}/.venv/bin/python"
    if [[ ! -x "${python_bin}" ]]; then
        python_bin="python3"
    fi

    # Start uvicorn with factory app
    nohup "${python_bin}" -m uvicorn logintel.api.app:create_app \
        --factory \
        --host 127.0.0.1 \
        --port 41721 \
        >> "${LOG_FILE}" 2>&1 &

    local new_pid=$!
    echo "${new_pid}" > "${PID_FILE}"

    # Verify startup
    sleep 2
    if is_running; then
        echo "[✓] LogIntel Engine daemon successfully started (PID: ${new_pid})."
        echo "    Endpoint: http://127.0.0.1:41721"
        echo "    Log File: ${LOG_FILE}"
    else
        echo "[✗] Failed to start LogIntel Engine. Check logs at: ${LOG_FILE}"
        cat "${LOG_FILE}" | tail -n 20
        exit 1
    fi
}

stop_daemon() {
    if ! is_running; then
        echo "[-] LogIntel Engine daemon is not running."
        rm -f "${PID_FILE}"
        return 0
    fi

    local pid
    pid="$(get_pid)"
    echo "[*] Stopping LogIntel Engine daemon (PID: ${pid})..."
    kill "${pid}" 2>/dev/null || true

    local count=0
    while kill -0 "${pid}" 2>/dev/null && [[ ${count} -lt 10 ]]; do
        sleep 1
        count=$((count + 1))
    done

    if kill -0 "${pid}" 2>/dev/null; then
        echo "[!] Forcing termination..."
        kill -9 "${pid}" 2>/dev/null || true
    fi

    rm -f "${PID_FILE}"
    echo "[✓] LogIntel Engine daemon stopped."
}

status_daemon() {
    if is_running; then
        local pid
        pid="$(get_pid)"
        echo "[✓] LogIntel Engine daemon is RUNNING (PID: ${pid})."
        echo "    Health: http://127.0.0.1:41721/handshake"
        echo "    Log:    ${LOG_FILE}"
    else
        echo "[✗] LogIntel Engine daemon is STOPPED."
    fi
}

case "${1:-status}" in
    start)
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        stop_daemon
        sleep 1
        start_daemon
        ;;
    status)
        status_daemon
        ;;
    logs)
        tail -f -n 50 "${LOG_FILE}"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac

