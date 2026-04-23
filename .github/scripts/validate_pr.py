#!/usr/bin/env python3
"""Validate bridge submissions in a PR diff.

Checks:
- Each touched bridge directory has all required files.
- manifest.json has all required fields and a valid id.
- Bridge id matches ^[a-z][a-z0-9-]{2,31}$ AND equals the directory name.
- Icon present (icon.png or icon.svg); PNG must be at least 128x128 px.
- CHANGELOG.md has an entry for the manifest version.
- The 'recommended' tag is not set on community PRs (reserved for maintainers).
- No external HTTPS URLs in the manifest (bridges must bundle their assets).

Usage: validate_pr.py <base-ref>
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,31}$")
REQUIRED_FIELDS = {"id", "name", "description", "version", "author", "entry"}
REQUIRED_FILES = {"manifest.json", "main.lua", "README.md", "CHANGELOG.md"}
RESERVED_TAGS = {"recommended"}
VALID_MESH_SUPPORT = {"none", "partial", "full"}
URL_FIELDS = {"thumbnail", "icon", "homepage", "readme"}  # fields that must NOT contain external URLs


def fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def changed_bridges(base: str) -> set[str]:
    diff = subprocess.check_output(
        ["git", "diff", "--name-only", f"{base}...HEAD"], text=True
    ).splitlines()
    ids: set[str] = set()
    for line in diff:
        parts = Path(line).parts
        if len(parts) >= 2 and parts[0] == "bridges":
            ids.add(parts[1])
    return ids


def check_bridge(bridge_dir: Path) -> None:
    if not bridge_dir.is_dir():
        return  # deletion case

    manifest_path = bridge_dir / "manifest.json"
    if not manifest_path.exists():
        fail(f"{bridge_dir}: manifest.json missing")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"{bridge_dir}/manifest.json: {e}")

    missing_fields = REQUIRED_FIELDS - set(manifest.keys())
    if missing_fields:
        fail(f"{bridge_dir}: missing required fields {sorted(missing_fields)}")

    if not ID_PATTERN.match(manifest["id"]):
        fail(f"{bridge_dir}: id '{manifest['id']}' does not match ^[a-z][a-z0-9-]{{2,31}}$")

    if manifest["id"] != bridge_dir.name:
        fail(f"{bridge_dir}: id '{manifest['id']}' does not match directory name '{bridge_dir.name}'")

    for fname in REQUIRED_FILES:
        if not (bridge_dir / fname).exists():
            fail(f"{bridge_dir}: {fname} missing")

    png = bridge_dir / "icon.png"
    svg = bridge_dir / "icon.svg"
    if not png.exists() and not svg.exists():
        fail(f"{bridge_dir}: icon.png or icon.svg required")

    if png.exists():
        try:
            out = subprocess.check_output(["identify", "-format", "%w %h", str(png)], text=True)
            w, h = (int(x) for x in out.strip().split())
            if w < 128 or h < 128:
                fail(f"{bridge_dir}: icon.png must be at least 128x128 (got {w}x{h})")
        except FileNotFoundError:
            print(f"WARN: imagemagick not installed; skipping icon dimension check for {bridge_dir}", file=sys.stderr)
        except (ValueError, subprocess.CalledProcessError) as e:
            fail(f"{bridge_dir}: failed to read icon.png dimensions: {e}")

    changelog = (bridge_dir / "CHANGELOG.md").read_text(encoding="utf-8")
    version = manifest["version"]
    if f"v{version}" not in changelog and version not in changelog:
        fail(f"{bridge_dir}: CHANGELOG.md has no entry for version {version}")

    mesh_support = manifest.get("mesh_support")
    if mesh_support is not None and mesh_support not in VALID_MESH_SUPPORT:
        fail(
            f"{bridge_dir}: mesh_support='{mesh_support}' is invalid — "
            f"must be one of {sorted(VALID_MESH_SUPPORT)} (or omit the field, which defaults to 'none')"
        )

    tags = manifest.get("tags", [])
    reserved_used = set(tags) & RESERVED_TAGS
    if reserved_used:
        fail(f"{bridge_dir}: reserved tags used {sorted(reserved_used)} — these are maintainer-only")

    for field in URL_FIELDS:
        val = manifest.get(field)
        if isinstance(val, str) and (val.startswith("http://") or val.startswith("https://")):
            fail(f"{bridge_dir}: field '{field}' contains external URL — assets must be bundled in the bridge directory")


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/main"
    ids = changed_bridges(base)
    if not ids:
        print("No bridge changes in diff.")
        return 0
    for bid in sorted(ids):
        bridge_dir = Path("bridges") / bid
        check_bridge(bridge_dir)
    print(f"OK: {len(ids)} bridge(s) validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
