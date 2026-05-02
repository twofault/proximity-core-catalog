#!/usr/bin/env python3
"""Regenerate index.json from bridges/ directory + existing GitHub Releases.

Enumerates `gh release list` + `gh release view <tag>` to find published
versions, then walks `bridges/<id>/` for manifest + changelog + icon.

Assumptions:
- Each release asset is named `<bridge-id>-<version>.zip`.
- The release body contains a line `sha256: <64 hex chars>` (appended by publish.yml).
- `CHANGELOG.md` uses the convention `## v<version>` or `## <version>` as section header.
"""
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = "twofault/proximity-core-catalog"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/main"
RELEASE_BASE = f"https://github.com/{REPO}/releases/download"
SCHEMA_VERSION = 1
MIN_APP_VERSION = "0.2.0"


def gh(*args: str) -> str:
    return subprocess.check_output(["gh", *args], text=True)


def list_releases() -> list[dict]:
    out = gh("release", "list", "--limit", "1000", "--json", "tagName,publishedAt")
    return json.loads(out)


def parse_tag(tag: str) -> tuple[str, str] | None:
    m = re.match(r"^([a-z][a-z0-9-]{2,31})/v(\d+\.\d+\.\d+)$", tag)
    return (m.group(1), m.group(2)) if m else None


def find_icon_url(bridge_dir: Path) -> str | None:
    for name in ("icon.png", "icon.svg"):
        if (bridge_dir / name).exists():
            return f"{RAW_BASE}/{bridge_dir.as_posix()}/{name}"
    return None


def parse_semver(s: str) -> tuple[int, int, int]:
    return tuple(int(x) for x in s.split("."))  # type: ignore


def extract_changelog(path: Path, version: str) -> str:
    if not path.exists():
        return ""
    content = path.read_text(encoding="utf-8")
    pattern = rf"##\s*v?{re.escape(version)}\b.*?\n([\s\S]*?)(?:\n##\s|\Z)"
    m = re.search(pattern, content)
    return m.group(1).strip() if m else ""


def release_metadata(tag: str, bridge_id: str, version: str) -> tuple[str, int] | None:
    """Return (sha256, size_bytes) for the asset `<bridge_id>-<version>.zip` under `tag`, or None if missing."""
    asset_name = f"{bridge_id}-{version}.zip"
    view = json.loads(gh("release", "view", tag, "--json", "assets,body"))
    asset = next((a for a in view["assets"] if a["name"] == asset_name), None)
    if not asset:
        print(f"WARN: asset {asset_name} missing for tag {tag}", file=sys.stderr)
        return None
    body = view.get("body", "")
    sha_match = re.search(r"sha256:\s*([a-f0-9]{64})", body)
    if not sha_match:
        print(f"WARN: sha256 missing from release body of {tag}", file=sys.stderr)
        return None
    return sha_match.group(1), asset["size"]


def build_entry(bridge_id: str, bridge_dir: Path, versions_for_bridge: list[tuple[str, str, str, int]]) -> dict:
    manifest = json.loads((bridge_dir / "manifest.json").read_text(encoding="utf-8"))
    changelog_path = bridge_dir / "CHANGELOG.md"

    versions = []
    for tag, published_at, sha256, size in versions_for_bridge:
        version = tag.split("/v")[-1]
        versions.append({
            "version": version,
            "released_at": published_at,
            "download_url": f"{RELEASE_BASE}/{tag}/{bridge_id}-{version}.zip",
            "sha256": sha256,
            "size_bytes": size,
            "changelog": extract_changelog(changelog_path, version),
            "min_app_version": MIN_APP_VERSION,
            "yanked": False,
            "game_engines": manifest.get("game_engines", []),
            "compatibility": manifest.get("compatibility", {}),
        })
    versions.sort(key=lambda v: parse_semver(v["version"]), reverse=True)
    latest_version = versions[0]["version"] if versions else None

    return {
        "id": bridge_id,
        "name": manifest["name"],
        "description": manifest["description"],
        "author": manifest["author"],
        "tags": manifest.get("tags", []),
        "icon_url": find_icon_url(bridge_dir),
        "readme_url": f"{RAW_BASE}/{bridge_dir.as_posix()}/README.md",
        "repository_url": f"https://github.com/{REPO}/tree/main/{bridge_dir.as_posix()}",
        "latest_version": latest_version,
        "versions": versions,
    }


def main() -> int:
    releases = list_releases()
    by_bridge: dict[str, list[tuple[str, str, str, int]]] = {}
    for rel in releases:
        parsed = parse_tag(rel["tagName"])
        if not parsed:
            continue
        bridge_id, version = parsed
        meta = release_metadata(rel["tagName"], bridge_id, version)
        if not meta:
            continue
        sha256, size = meta
        by_bridge.setdefault(bridge_id, []).append(
            (rel["tagName"], rel["publishedAt"], sha256, size)
        )

    bridges = []
    for bridge_id, versions in sorted(by_bridge.items()):
        bridge_dir = Path("bridges") / bridge_id
        if not (bridge_dir / "manifest.json").exists():
            print(f"WARN: no manifest for {bridge_id}; skipping", file=sys.stderr)
            continue
        bridges.append(build_entry(bridge_id, bridge_dir, versions))

    index = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "min_app_version": MIN_APP_VERSION,
        "bridges": bridges,
    }
    Path("index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote index.json with {len(bridges)} bridges")
    return 0


if __name__ == "__main__":
    sys.exit(main())
