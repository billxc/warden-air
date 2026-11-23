#!/bin/zsh
set -euo pipefail

HOST_NAME="io.github.billxc.warden_air"
EXTENSION_ID="nphekoiaefcbmdmoknadaohgnloneeaj"
RAW_BASE="${WARDEN_AIR_RAW_BASE:-https://raw.githubusercontent.com/billxc/warden-air/main}"
INSTALL_DIR="$HOME/.config/warden-air/host"

if [[ "${1:-}" == "--local" ]]; then
  SCRIPT_DIR="${0:A:h}"
  HOST_DIR="${SCRIPT_DIR:h}/host"
  chmod +x "$HOST_DIR/run-host.sh" "$HOST_DIR/host.mjs" "$HOST_DIR/agent.mjs"
else
  HOST_DIR="$INSTALL_DIR"
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT

  print "Downloading Warden Air host from GitHub..."
  for file in agent.mjs host.mjs paths.mjs vault.mjs run-host.sh; do
    curl -fsSL "$RAW_BASE/host/$file" -o "$TMP_DIR/$file"
  done

  mkdir -p "$HOST_DIR"
  for file in agent.mjs host.mjs paths.mjs vault.mjs run-host.sh; do
    mv "$TMP_DIR/$file" "$HOST_DIR/$file"
  done
  chmod +x "$HOST_DIR/run-host.sh" "$HOST_DIR/host.mjs" "$HOST_DIR/agent.mjs"
  print "Installed host files to: $HOST_DIR"
fi

HOST_BIN="$HOST_DIR/run-host.sh"
APP_SUPPORT="$HOME/Library/Application Support"

typeset -a BROWSER_DIRS=(
  "$APP_SUPPORT/Google/Chrome"
  "$APP_SUPPORT/Google/Chrome Beta"
  "$APP_SUPPORT/Google/Chrome Dev"
  "$APP_SUPPORT/Google/Chrome Canary"
  "$APP_SUPPORT/Chromium"
  "$APP_SUPPORT/Microsoft Edge"
  "$APP_SUPPORT/Microsoft Edge Beta"
  "$APP_SUPPORT/Microsoft Edge Dev"
  "$APP_SUPPORT/Microsoft Edge Canary"
  "$APP_SUPPORT/BraveSoftware/Brave-Browser"
  "$APP_SUPPORT/BraveSoftware/Brave-Browser-Beta"
  "$APP_SUPPORT/BraveSoftware/Brave-Browser-Nightly"
  "$APP_SUPPORT/Arc/User Data"
  "$APP_SUPPORT/Vivaldi"
  "$APP_SUPPORT/Dia/User Data"
  "$APP_SUPPORT/net.imput.helium"
)

installed_count=0
for dir in "${BROWSER_DIRS[@]}"; do
  if [[ -d "$dir" ]]; then
    nmh_dir="$dir/NativeMessagingHosts"
    mkdir -p "$nmh_dir"
    manifest_file="$nmh_dir/$HOST_NAME.json"
    cat > "$manifest_file" <<EOF
{
  "name": "$HOST_NAME",
  "description": "Warden Air native messaging host",
  "path": "$HOST_BIN",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$EXTENSION_ID/"
  ]
}
EOF
    print "Registered: $manifest_file"
    (( installed_count += 1 ))
  fi
done

if [[ -S "$HOME/.config/warden-air/agent.sock" ]]; then
  python3 -I -c '
import json, os, socket, struct
sock_path = os.path.expanduser("~/.config/warden-air/agent.sock")
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(0.5)
    s.connect(sock_path)
    body = json.dumps({"id": 1, "action": "shutdown"}).encode()
    s.sendall(struct.pack("<I", len(body)) + body)
    s.recv(64)
    s.close()
except Exception:
    pass
' 2>/dev/null || true
fi

print "Done. Registered $HOST_NAME in $installed_count browser(s)."

BW_DATA="$HOME/Library/Application Support/Bitwarden/data.json"
if [[ -f "$BW_DATA" ]]; then
  if ! grep -q '"global_autofillSettings_enableDuckDuckGoBrowserIntegration":[[:space:]]*true' "$BW_DATA" 2>/dev/null; then
    print "Tip: Enable 'Allow DuckDuckGo browser integration' in Bitwarden Desktop -> Settings to support password saving."
  fi
fi
