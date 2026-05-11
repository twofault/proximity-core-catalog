#!/usr/bin/env python3
"""Delete old GitHub Releases per bridge.

For each bridge, keep the newest `release_keep_count` versions (by semver,
desc). Older releases AND their tags are deleted. Run from
`regenerate-index.yml` after `index.json` has been committed, so users on
the catalog never see a download URL for a release that no longer exists.

Pass `--dry-run` (or set `CATALOG_PRUNE_DRY_RUN=1`) to print what would be
deleted without actually deleting. Useful before flipping the workflow on
for the first time.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = json.loads((REPO_ROOT / "catalog.config.json").read_text(encoding="utf-8"))
REPO = CONFIG["repo"]
KEEP = int(CONFIG.get("release_keep_count", 10))
TAG_RE = re.compile(r"^([a-z][a-z0-9-]{2,31})/v(\d+\.\d+\.\d+)$")


def gh_json(*args: str) -> list | dict:
    out = subprocess.check_output(["gh", *args], text=True)
    return json.loads(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be deleted but do nothing")
    args = parser.parse_args()
    dry_run = args.dry_run or os.environ.get("CATALOG_PRUNE_DRY_RUN") == "1"

    releases = gh_json(
        "release", "list", "--repo", REPO, "--limit", "1000",
        "--json", "tagName,createdAt",
    )
    by_bridge: dict[str, list[tuple[str, tuple[int, int, int]]]] = {}
    for rel in releases:
        m = TAG_RE.match(rel["tagName"])
        if not m:
            continue
        bid, ver = m.group(1), m.group(2)
        sv = tuple(int(x) for x in ver.split("."))  # type: ignore[assignment]
        by_bridge.setdefault(bid, []).append((rel["tagName"], sv))

    pruned = 0
    for bid, items in by_bridge.items():
        items.sort(key=lambda x: x[1], reverse=True)
        for tag, _ in items[KEEP:]:
            verb = "DRY-RUN would prune" if dry_run else "prune"
            print(f"  {verb} {tag}")
            if not dry_run:
                subprocess.run(
                    ["gh", "release", "delete", tag, "--repo", REPO,
                     "--yes", "--cleanup-tag"],
                    check=False,
                )
            pruned += 1
    suffix = " (dry-run; nothing deleted)" if dry_run else ""
    print(f"Pruned {pruned} releases (keep={KEEP} per bridge){suffix}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
