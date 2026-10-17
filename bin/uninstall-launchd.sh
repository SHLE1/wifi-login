#!/usr/bin/env bash
set -euo pipefail

readonly PLIST_PATH="$HOME/Library/LaunchAgents/com.github.shle1.wifi-login.plist"

main() {
  if [[ ! -f "$PLIST_PATH" ]]; then
    echo "LaunchAgent not found: $PLIST_PATH"
    return 0
  fi

  launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
  rm -f "$PLIST_PATH"
  echo "Removed LaunchAgent: $PLIST_PATH"
}

main "$@"
