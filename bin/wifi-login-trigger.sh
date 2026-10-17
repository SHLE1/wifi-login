#!/usr/bin/env bash
# WiFi 自动登录触发脚本
# 当连接到目标 WiFi（SSID_TARGET）时自动运行登录脚本

set -euo pipefail

readonly PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SRC_DIR="$PROJECT_DIR/src"
readonly LOG_DIR="$PROJECT_DIR/logs"
readonly LOG_FILE="$LOG_DIR/trigger.log"
readonly SSID_TARGET="YOUR_TARGET_SSID"  # 改成你的 WiFi 名称

# 确保日志目录存在
mkdir -p "$LOG_DIR"

RUNNER=()

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# 获取当前 SSID
get_current_ssid() {
    local en
    en="$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $NF}')"
    ipconfig getsummary "$en" | grep -Fxq "  Active : FALSE" || networksetup -listpreferredwirelessnetworks "$en" | sed -n '2s/^\t//p'
}

resolve_python_runner() {
    if command -v uv >/dev/null 2>&1; then
        RUNNER=(uv run --project "$PROJECT_DIR" python)
        return 0
    fi

    if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
        RUNNER=("$PROJECT_DIR/.venv/bin/python")
        return 0
    fi

    if [[ -x "$PROJECT_DIR/venv/bin/python" ]]; then
        RUNNER=("$PROJECT_DIR/venv/bin/python")
        return 0
    fi

    return 1
}

run_login() {
    local exit_code

    cd "$PROJECT_DIR"
    PYTHONPATH="$SRC_DIR${PYTHONPATH:+:$PYTHONPATH}" "${RUNNER[@]}" -m wifi_auto_login.cli >> "$LOG_FILE" 2>&1
    exit_code=$?
    log "Login script completed with exit code: $exit_code"
}

main() {
    local current_ssid

    current_ssid=$(get_current_ssid)
    if [[ "$current_ssid" != "$SSID_TARGET" ]]; then
        log "Not connected to $SSID_TARGET (current: $current_ssid), skipping"
        return 0
    fi

    log "Connected to $SSID_TARGET, running login script..."

    # 等待网络稳定
    sleep 2

    if ! resolve_python_runner; then
        log "No Python runner found. Install uv or create .venv/venv first."
        exit 1
    fi

    run_login
}

main "$@"
