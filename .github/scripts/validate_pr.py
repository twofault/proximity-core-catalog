#!/usr/bin/env python3
"""Validate bridge submissions.

Two modes:

  CI mode:    validate_pr.py <base-ref>
              Validates every bridge touched in the PR diff against <base-ref>,
              plus every bridge that depends on a changed `shared/` file via its
              `.catalog-vendor.json`. Reads $GITHUB_PR_AUTHOR and $GITHUB_REPOSITORY
              from the environment to enforce the reserved-tag policy.

  Local mode: validate_pr.py --bridge bridges/<id>
              Validates a single bridge directory. Reserved-tag policy is skipped
              (no PR context). Use this before opening a PR.

Checks:
- All required files present (manifest.json, main.lua, README.md, CHANGELOG.md, icon).
- Icon: png at least 128x128, or svg.
- manifest.json schema:
    * required fields, valid id (regex + matches dir name).
    * `entry` points at an existing .lua file inside the bridge dir.
    * `gamelink_script` (if set) points at an existing .lua file.
    * `capabilities.uses_blockable_apis` + `capabilities.uses_game_session` are bool.
    * `http_endpoints` are all https:// strings.
    * `game_session_support` is one of {none, partial, full} if set.
    * `bridge_scope` is one of {game_specific, generic} if set.
    * `tags` is a list of strings.
    * No external URLs in cosmetic fields.
- CHANGELOG.md contains an entry for the manifest version.
- `.catalog-vendor.json` (if present) declares only files under `shared/`, all of
  which exist.
- Reserved tags (configured in catalog.config.json) only allowed when the PR
  author has write+ permission on the repo. The catalog's own bridges retain
  reserved tags because direct pushes to main bypass this validator.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,31}$")
REQUIRED_FIELDS = {"id", "name", "description", "version", "author", "entry"}
REQUIRED_FILES = {"manifest.json", "main.lua", "README.md", "CHANGELOG.md"}
VALID_GAME_SESSION_SUPPORT = {"none", "partial", "full"}
VALID_BRIDGE_SCOPE = {"game_specific", "generic"}
COSMETIC_URL_FIELDS = {"thumbnail", "icon", "homepage", "readme"}
# PR `author_association` values that count as "maintainer" for reserved-tag policy.
# Reference: https://docs.github.com/en/graphql/reference/enums#commentauthorassociation
MAINTAINER_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPO_ROOT / "catalog.config.json"


def fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def _safe_lua_relpath(path: str) -> bool:
    """A relative .lua path with no traversal and no leading separator."""
    if not path or not path.endswith(".lua"):
        return False
    p = Path(path)
    if p.is_absolute():
        return False
    if path.startswith("/") or path.startswith("\\"):
        return False
    return ".." not in p.parts and "" not in p.parts


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        fail(f"catalog.config.json missing at {CONFIG_PATH}")
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def changed_paths(base: str) -> list[Path]:
    out = subprocess.check_output(
        ["git", "diff", "--name-only", f"{base}...HEAD"], text=True
    )
    return [Path(line) for line in out.splitlines() if line.strip()]


def bridges_touching_shared(changed: list[Path]) -> set[str]:
    """For each changed file under `shared/`, find bridges that vendor it."""
    touched_shared = {p.as_posix() for p in changed if p.parts and p.parts[0] == "shared"}
    if not touched_shared:
        return set()
    affected: set[str] = set()
    bridges_dir = REPO_ROOT / "bridges"
    if not bridges_dir.is_dir():
        return affected
    for bridge_dir in bridges_dir.iterdir():
        spec = bridge_dir / ".catalog-vendor.json"
        if not spec.is_file():
            continue
        try:
            data = json.loads(spec.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        sources = set((data.get("lua") or {}).keys())
        if sources & touched_shared:
            affected.add(bridge_dir.name)
    return affected


def changed_bridges(changed: list[Path]) -> set[str]:
    ids: set[str] = set()
    for path in changed:
        parts = path.parts
        if len(parts) >= 2 and parts[0] == "bridges":
            ids.add(parts[1])
    return ids


def check_vendor_spec(bridge_dir: Path) -> None:
    spec_path = bridge_dir / ".catalog-vendor.json"
    if not spec_path.exists():
        return
    try:
        data = json.loads(spec_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"{bridge_dir}/.catalog-vendor.json: {e}")

    lua = data.get("lua") or {}
    if not isinstance(lua, dict):
        fail(f"{bridge_dir}/.catalog-vendor.json: 'lua' must be an object")

    shared_root = (REPO_ROOT / "shared").resolve()
    for source, dest in lua.items():
        if not isinstance(source, str) or not isinstance(dest, str):
            fail(f"{bridge_dir}/.catalog-vendor.json: lua entries must be string -> string")
        # Source must resolve under shared/. resolve() collapses any '..' so a
        # path crafted to escape is caught even if it doesn't literally contain
        # '..' (e.g. via symlinks committed by mistake).
        src_resolved = (REPO_ROOT / source).resolve()
        try:
            src_resolved.relative_to(shared_root)
        except ValueError:
            fail(f"{bridge_dir}/.catalog-vendor.json: source '{source}' must resolve under shared/")
        if not src_resolved.is_file():
            fail(f"{bridge_dir}/.catalog-vendor.json: source '{source}' does not exist")
        # Dest must be a relative .lua path that resolves under the bridge dir.
        if not _safe_lua_relpath(dest):
            fail(f"{bridge_dir}/.catalog-vendor.json: dest '{dest}' must be a relative .lua path "
                 f"inside the bridge (no '..', no leading '/')")


def is_maintainer_pr() -> bool:
    """`author_association` from the PR event is the cheapest, most reliable
    signal for maintainer status. No extra API call, no extra token scope."""
    assoc = os.environ.get("GITHUB_PR_AUTHOR_ASSOCIATION", "").upper()
    return assoc in MAINTAINER_ASSOCIATIONS


def check_bridge(bridge_dir: Path, config: dict, *, enforce_reserved: bool, pr_is_maintainer: bool) -> None:
    if not bridge_dir.is_dir():
        return  # deletion case

    manifest_path = bridge_dir / "manifest.json"
    if not manifest_path.exists():
        fail(f"{bridge_dir}: manifest.json missing")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"{bridge_dir}/manifest.json: {e}")

    missing = REQUIRED_FIELDS - set(manifest.keys())
    if missing:
        fail(f"{bridge_dir}: missing required fields {sorted(missing)}")

    if not ID_PATTERN.match(manifest["id"]):
        fail(f"{bridge_dir}: id '{manifest['id']}' does not match ^[a-z][a-z0-9-]{{2,31}}$")
    if manifest["id"] != bridge_dir.name:
        fail(f"{bridge_dir}: id '{manifest['id']}' does not match directory name '{bridge_dir.name}'")

    if not SEMVER_RE.match(manifest["version"]):
        fail(f"{bridge_dir}: version '{manifest['version']}' must be MAJOR.MINOR.PATCH (numeric only)")

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

    entry = manifest["entry"]
    if not isinstance(entry, str):
        fail(f"{bridge_dir}: entry must be a string")
    if not _safe_lua_relpath(entry):
        fail(f"{bridge_dir}: entry '{entry}' must be a relative .lua path inside the bridge "
             f"(no '..', no leading '/', no path-escaping)")
    if not (bridge_dir / entry).exists():
        fail(f"{bridge_dir}: entry file '{entry}' does not exist")

    gl_script = manifest.get("gamelink_script")
    if gl_script is not None:
        if not isinstance(gl_script, str):
            fail(f"{bridge_dir}: gamelink_script must be a string")
        if not _safe_lua_relpath(gl_script):
            fail(f"{bridge_dir}: gamelink_script '{gl_script}' must be a relative .lua path "
                 f"inside the bridge (no '..', no leading '/', no path-escaping)")
        vendored = False
        spec = bridge_dir / ".catalog-vendor.json"
        if spec.is_file():
            data = json.loads(spec.read_text(encoding="utf-8"))
            if gl_script in (data.get("lua") or {}).values():
                vendored = True
        if not vendored and not (bridge_dir / gl_script).exists():
            fail(f"{bridge_dir}: gamelink_script '{gl_script}' does not exist (and is not vendored)")

    caps = manifest.get("capabilities") or {}
    if not isinstance(caps, dict):
        fail(f"{bridge_dir}: 'capabilities' must be an object")
    for key in ("uses_blockable_apis", "uses_game_session"):
        if key in caps and not isinstance(caps[key], bool):
            fail(f"{bridge_dir}: capabilities.{key} must be a boolean")

    endpoints = manifest.get("http_endpoints") or []
    if not isinstance(endpoints, list):
        fail(f"{bridge_dir}: 'http_endpoints' must be a list")
    for url in endpoints:
        if not isinstance(url, str):
            fail(f"{bridge_dir}: http_endpoints entries must be strings")
        if not url.startswith("https://"):
            fail(f"{bridge_dir}: http_endpoints '{url}' must be https://")

    gss = manifest.get("game_session_support")
    if gss is not None and gss not in VALID_GAME_SESSION_SUPPORT:
        fail(f"{bridge_dir}: game_session_support='{gss}' must be one of {sorted(VALID_GAME_SESSION_SUPPORT)}")

    scope = manifest.get("bridge_scope")
    if scope is not None and scope not in VALID_BRIDGE_SCOPE:
        fail(f"{bridge_dir}: bridge_scope='{scope}' must be one of {sorted(VALID_BRIDGE_SCOPE)}")

    tags = manifest.get("tags") or []
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        fail(f"{bridge_dir}: 'tags' must be a list of strings")

    if enforce_reserved:
        reserved = set(config.get("reserved_tags") or [])
        used = set(tags) & reserved
        if used and not pr_is_maintainer:
            fail(
                f"{bridge_dir}: reserved tags {sorted(used)} can only be granted by maintainers. "
                f"Please remove them from manifest.json — a maintainer may re-add them on merge."
            )

    for field in COSMETIC_URL_FIELDS:
        val = manifest.get(field)
        if isinstance(val, str) and val.startswith(("http://", "https://")):
            fail(f"{bridge_dir}: field '{field}' contains external URL — assets must be bundled in the bridge directory")

    changelog = (bridge_dir / "CHANGELOG.md").read_text(encoding="utf-8")
    version = manifest["version"]
    if f"v{version}" not in changelog and version not in changelog:
        fail(f"{bridge_dir}: CHANGELOG.md has no entry for version {version}")

    check_vendor_spec(bridge_dir)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("base", nargs="?", help="Base git ref to diff against (CI mode)")
    parser.add_argument("--bridge", help="Path to a single bridge directory to validate (local mode)")
    args = parser.parse_args()

    config = load_config()

    if args.bridge:
        bridge_dir = Path(args.bridge)
        if not bridge_dir.is_dir():
            fail(f"{bridge_dir}: not a directory")
        check_bridge(bridge_dir, config, enforce_reserved=False, pr_is_maintainer=True)
        print(f"OK: validated {bridge_dir} (local mode — reserved-tag policy skipped)")
        return 0

    base = args.base or "origin/main"
    diff = changed_paths(base)
    ids = changed_bridges(diff) | bridges_touching_shared(diff)
    if not ids:
        print("No bridge or shared/ changes in diff.")
        return 0

    pr_is_maintainer = is_maintainer_pr()
    for bid in sorted(ids):
        check_bridge(REPO_ROOT / "bridges" / bid, config, enforce_reserved=True, pr_is_maintainer=pr_is_maintainer)
    print(f"OK: {len(ids)} bridge(s) validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
