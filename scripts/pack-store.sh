#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR:h}"
EXT_DIR="$REPO_ROOT/extension"

VERSION=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).version)' "$EXT_DIR/manifest.json")
OUT_ZIP="${1:-$REPO_ROOT/.scratch/store/warden-air-store-v${VERSION}.zip}"
OUT_ZIP="${OUT_ZIP:A}"
mkdir -p "${OUT_ZIP:h}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cp -R "$EXT_DIR/." "$TMP_DIR/"
rm -f "$TMP_DIR/.DS_Store" "$TMP_DIR/icons/.DS_Store" "$TMP_DIR/icons/icon.svg"

node -e '
const fs = require("fs");
const p = process.argv[1];
const manifest = JSON.parse(fs.readFileSync(p, "utf8"));
delete manifest.key;
fs.writeFileSync(p, JSON.stringify(manifest, null, 2) + "\n");
' "$TMP_DIR/manifest.json"

rm -f "$OUT_ZIP"
(cd "$TMP_DIR" && zip -q -r "$OUT_ZIP" .)
print "Packed: $OUT_ZIP"
