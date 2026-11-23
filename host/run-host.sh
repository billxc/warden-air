#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
typeset -a NVM_NODES=("$HOME"/.nvm/versions/node/*/bin/node(NOn))

for candidate in \
  /opt/homebrew/bin/node \
  /usr/local/bin/node \
  "$HOME/.volta/bin/node" \
  "$HOME/.local/share/fnm/aliases/default/bin/node" \
  "${NVM_NODES[1]:-}"; do
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    exec "$candidate" "$SCRIPT_DIR/host.mjs" "$@"
  fi
done

exec node "$SCRIPT_DIR/host.mjs" "$@"
