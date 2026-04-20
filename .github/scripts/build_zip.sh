#!/usr/bin/env bash
# Usage: build_zip.sh <bridge-id> <version>
# Produces deterministic:
#   dist/<bridge-id>-<version>.zip
#   dist/<bridge-id>-<version>.zip.sha256
set -euo pipefail

BRIDGE_ID="$1"
VERSION="$2"
SRC="bridges/${BRIDGE_ID}"
OUT_DIR="dist"
OUT="${OUT_DIR}/${BRIDGE_ID}-${VERSION}.zip"

if [ ! -d "$SRC" ]; then
  echo "ERROR: bridge source not found at $SRC" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
rm -f "$OUT" "${OUT}.sha256"

# Deterministic zip:
#   -X  strip extra fields (timestamps etc)
#   -D  no data descriptors
#   -r  recurse
# Entries are added in sorted order by `find | sort`.
(
  cd "$(dirname "$SRC")"
  TZ=UTC find "$(basename "$SRC")" -type f | LC_ALL=C sort > ../.build_list.txt
  TZ=UTC zip -X -D -q "../${OUT}" -@ < ../.build_list.txt
  rm -f ../.build_list.txt
)

sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"
echo "Built $OUT"
echo "sha256: $(cat "${OUT}.sha256")"
