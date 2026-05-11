#!/usr/bin/env bash
# Usage: build_zip.sh <bridge-id> <version>
#
# Builds a deterministic zip:
#   dist/<bridge-id>-<version>.zip
#   dist/<bridge-id>-<version>.zip.sha256
#
# If `bridges/<bridge-id>/.catalog-vendor.json` is present, files declared
# under `lua` are copied from `shared/` into a staging directory before zipping.
# The staged directory is what gets archived, so vendored files appear as plain
# top-level files inside the zip.
set -euo pipefail

BRIDGE_ID="$1"
VERSION="$2"
SRC="bridges/${BRIDGE_ID}"
OUT_DIR="dist"
OUT="${OUT_DIR}/${BRIDGE_ID}-${VERSION}.zip"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

cd "$REPO_ROOT"

if [ ! -d "$SRC" ]; then
  echo "ERROR: bridge source not found at $SRC" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
rm -f "$OUT" "${OUT}.sha256"

STAGE_PARENT="$(mktemp -d -t catalog-build.XXXXXX)"
STAGE="${STAGE_PARENT}/${BRIDGE_ID}"
trap 'rm -rf "$STAGE_PARENT"' EXIT

# Copy bridge sources, excluding the vendor manifest itself (build-time only).
rsync -a --exclude='.catalog-vendor.json' "${SRC}/" "${STAGE}/"

# Apply vendor spec, if any. Containment-checks the spec independently of
# validate_pr.py — the spec might have reached `main` via a direct push, a
# bad merge, or future workflow changes. Builder must not trust it.
SPEC="${SRC}/.catalog-vendor.json"
if [ -f "$SPEC" ]; then
  SPEC_PATH="$SPEC" STAGE_PATH="$STAGE" REPO_ROOT_PATH="$REPO_ROOT" python3 - <<'EOF'
import json, os, shutil, sys
from pathlib import Path

spec_path = Path(os.environ["SPEC_PATH"])
stage = Path(os.environ["STAGE_PATH"]).resolve()
repo_root = Path(os.environ["REPO_ROOT_PATH"]).resolve()
shared_root = (repo_root / "shared").resolve()

spec = json.loads(spec_path.read_text())
for source, dest in (spec.get("lua") or {}).items():
    if not isinstance(source, str) or not isinstance(dest, str):
        sys.exit(f"vendor: lua entries must be string -> string (got {source!r}: {dest!r})")
    src = (repo_root / source).resolve()
    try:
        src.relative_to(shared_root)
    except ValueError:
        sys.exit(f"vendor: source '{source}' must live under shared/")
    if not src.is_file():
        sys.exit(f"vendor: source '{source}' missing")
    out = (stage / dest).resolve()
    try:
        out.relative_to(stage)
    except ValueError:
        sys.exit(f"vendor: dest '{dest}' escapes the bridge stage dir")
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, out)
EOF
fi

# Pin mtimes so identical source produces identical zips, regardless of when
# the workspace was checked out.
find "$STAGE" -exec touch -t 197001010000.00 {} +

(
  cd "$STAGE_PARENT"
  TZ=UTC find "${BRIDGE_ID}" -type f | LC_ALL=C sort > .build_list.txt
  TZ=UTC zip -X -D -q "${REPO_ROOT}/${OUT}" -@ < .build_list.txt
  rm -f .build_list.txt
)

sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"
echo "Built $OUT"
echo "sha256: $(cat "${OUT}.sha256")"
