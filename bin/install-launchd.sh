#!/usr/bin/env bash
set -euo pipefail

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly PLIST_LABEL="com.github.shle1.wifi-login"
readonly PLIST_TEMPLATE="$PROJECT_ROOT/launchd/com.github.shle1.wifi-login.plist"
readonly LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
readonly PLIST_PATH="$LAUNCH_AGENTS_DIR/${PLIST_LABEL}.plist"

render_plist() {
  local escaped_project_root
  escaped_project_root="${PROJECT_ROOT//&/\\&}"
  sed "s|__PROJECT_ROOT__|${escaped_project_root}|g" "$PLIST_TEMPLATE" > "$PLIST_PATH"
}

main() {
  mkdir -p "$LAUNCH_AGENTS_DIR" "$PROJECT_ROOT/logs"

  if [[ ! -f "$PLIST_TEMPLATE" ]]; then
    echo "LaunchAgent template not found: $PLIST_TEMPLATE" >&2
    exit 1
  fi

  render_plist

  launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
  launchctl load "$PLIST_PATH"

  echo "Installed LaunchAgent: $PLIST_PATH"
}

main "$@"
