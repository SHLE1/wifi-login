#!/bin/bash
# WiFi 自动登录触发脚本
# 当连接到目标 SSID 时自动运行登录脚本

set -e

PROJECT_DIR="/path/to/wifi-login"
LOG_FILE="$PROJECT_DIR/logs/trigger.log"
SSID_TARGET="YOUR_SSID"

# 确保日志目录存在
mkdir -p "$PROJECT_DIR/logs"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# 获取当前 SSID
get_current_ssid() {
    /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | awk '/ SSID/ {print $2}'
}

CURRENT_SSID=$(get_current_ssid)

if [ "$CURRENT_SSID" = "$SSID_TARGET" ]; then
    log "Connected to $SSID_TARGET, running login script..."

    # 等待网络稳定
    sleep 2

    # 使用 uv 运行 Python 脚本
    cd "$PROJECT_DIR"
    if command -v uv &> /dev/null; then
        uv run python scripts/wifi_portal_login.py >> "$LOG_FILE" 2>&1
    else
        # 回退到 venv
        source .venv/bin/activate
        python scripts/wifi_portal_login.py >> "$LOG_FILE" 2>&1
    fi

    log "Login script completed with exit code: $?"
else
    log "Not connected to $SSID_TARGET (current: $CURRENT_SSID), skipping"
fi
