#!/usr/bin/env python3
"""Regenerate index.json from bridges/ + GitHub Releases.

Reads `catalog.config.json` for repo identity. For every release tagged
`<bridge-id>/v<version>` that has an asset, hashes the actual asset bytes
to compute SHA-256 — never trusts the release body or any sidecar string.

Yank state lives at `yanks.json`. Entries flip `yanked: true` on the
matching version and carry a `yank_reason` string.
"""
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPO_ROOT / "catalog.config.json"
YANKS_PATH = REPO_ROOT / "yanks.json"
SCHEMA_VERSION = 1


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def gh(*args: str) -> str:
    return subprocess.check_output(["gh", *args], text=True)


def list_releases(repo: str) -> list[dict]:
    out = gh("release", "list", "--repo", repo, "--limit", "1000",
            "--json", "tagName,publishedAt")
    return json.loads(out)


def parse_tag(tag: str) -> tuple[str, str] | None:
    m = re.match(r"^([a-z][a-z0-9-]{2,31})/v(\d+\.\d+\.\d+)$", tag)
    return (m.group(1), m.group(2)) if m else None


def find_icon_url(bridge_id: str, bridge_dir: Path, raw_base: str) -> str | None:
    for name in ("icon.png", "icon.svg"):
        if (bridge_dir / name).exists():
            return f"{raw_base}/bridges/{bridge_id}/{name}"
    return None


def parse_semver(s: str) -> tuple[int, int, int]:
    return tuple(int(x) for x in s.split("."))  # type: ignore[return-value]


def extract_changelog(path: Path, version: str) -> str:
    if not path.exists():
        return ""
    content = path.read_text(encoding="utf-8")
    pattern = rf"##\s*v?{re.escape(version)}\b.*?\n([\s\S]*?)(?:\n##\s|\Z)"
    m = re.search(pattern, content)
    return m.group(1).strip() if m else ""


def fetch_and_hash_asset(repo: str, tag: str, bridge_id: str, version: str) -> tuple[str, int] | None:
    """Download the asset via `gh release download` and hash its actual bytes.

    `gh` handles auth for both public and private repos via the configured
    token — `urllib.request` against `asset["url"]` would silently fail on
    private forks.
    """
    asset_name = f"{bridge_id}-{version}.zip"
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        result = subprocess.run(
            ["gh", "release", "download", tag, "--repo", repo,
             "--pattern", asset_name, "--dir", str(tmp_path)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"WARN: download failed for {tag}/{asset_name}: {result.stderr.strip()}", file=sys.stderr)
            return None
        path = tmp_path / asset_name
        if not path.is_file():
            print(f"WARN: asset {asset_name} not in release {tag}", file=sys.stderr)
            return None
        data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def load_yanks() -> dict:
    if not YANKS_PATH.exists():
        return {}
    return json.loads(YANKS_PATH.read_text(encoding="utf-8"))


def build_entry(
    bridge_id: str,
    bridge_dir: Path,
    versions_for_bridge: list[tuple[str, str, str, int]],
    config: dict,
    yanks: dict,
    *,
    raw_base: str,
    release_base: str,
    repo: str,
) -> dict:
    manifest = json.loads((bridge_dir / "manifest.json").read_text(encoding="utf-8"))
    changelog_path = bridge_dir / "CHANGELOG.md"
    bridge_yanks = yanks.get(bridge_id) or {}

    versions = []
    for tag, published_at, sha256, size in versions_for_bridge:
        version = tag.split("/v")[-1]
        yank_info = bridge_yanks.get(version) or {}
        yanked = bool(yank_info.get("yanked", False))
        versions.append({
            "version": version,
            "released_at": published_at,
            "download_url": f"{release_base}/{tag}/{bridge_id}-{version}.zip",
            "sha256": sha256,
            "size_bytes": size,
            "changelog": extract_changelog(changelog_path, version),
            "min_app_version": config["min_app_version"],
            "yanked": yanked,
            "yank_reason": yank_info.get("reason", "") if yanked else "",
            "game_engines": manifest.get("game_engines", []),
            "compatibility": manifest.get("compatibility", {}),
        })
    versions.sort(key=lambda v: parse_semver(v["version"]), reverse=True)

    # latest_version skips yanked entries.
    latest = next((v["version"] for v in versions if not v["yanked"]), None)
    if latest is None and versions:
        latest = versions[0]["version"]

    return {
        "id": bridge_id,
        "name": manifest["name"],
        "description": manifest["description"],
        "author": manifest["author"],
        "tags": manifest.get("tags", []),
        "icon_url": find_icon_url(bridge_id, bridge_dir, raw_base),
        "readme_url": f"{raw_base}/bridges/{bridge_id}/README.md",
        "repository_url": f"https://github.com/{repo}/tree/{config['default_branch']}/bridges/{bridge_id}",
        "latest_version": latest,
        "versions": versions,
    }


def main() -> int:
    config = load_config()
    repo = config["repo"]
    raw_base = f"https://raw.githubusercontent.com/{repo}/{config['default_branch']}"
    release_base = f"https://github.com/{repo}/releases/download"

    releases = list_releases(repo)
    yanks = load_yanks()
    by_bridge: dict[str, list[tuple[str, str, str, int]]] = {}
    for rel in releases:
        parsed = parse_tag(rel["tagName"])
        if not parsed:
            continue
        bridge_id, version = parsed
        meta = fetch_and_hash_asset(repo, rel["tagName"], bridge_id, version)
        if not meta:
            continue
        sha256, size = meta
        by_bridge.setdefault(bridge_id, []).append(
            (rel["tagName"], rel["publishedAt"], sha256, size)
        )

    bridges = []
    for bridge_id, versions in sorted(by_bridge.items()):
        bridge_dir = REPO_ROOT / "bridges" / bridge_id
        if not (bridge_dir / "manifest.json").exists():
            print(f"WARN: no manifest for {bridge_id}; skipping", file=sys.stderr)
            continue
        bridges.append(build_entry(
            bridge_id, bridge_dir, versions, config, yanks,
            raw_base=raw_base, release_base=release_base, repo=repo,
        ))

    index = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "min_app_version": config["min_app_version"],
        "bridges": bridges,
    }
    (REPO_ROOT / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote index.json with {len(bridges)} bridges")
    return 0


if __name__ == "__main__":
    sys.exit(main())
