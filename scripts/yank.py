#!/usr/bin/env python3
"""Yank a released bridge version.

Marks a version as `yanked: true` in `yanks.json` (created if absent). The
next `regenerate_index.py` run picks it up; the app filters yanked versions
out of update candidates.

The release asset stays downloadable so users with the bad version pinned
can still verify it byte-for-byte. To actually take it offline, also delete
the GitHub release (or wait for prune_releases to do so).

Usage:
    scripts/yank.py <bridge-id> <version> --reason "..."
    scripts/yank.py <bridge-id> <version> --unyank
"""
import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
YANKS_PATH = REPO_ROOT / "yanks.json"
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bridge")
    parser.add_argument("version")
    parser.add_argument("--reason", help="Why this version is being yanked (required to yank)")
    parser.add_argument("--unyank", action="store_true", help="Remove an existing yank")
    args = parser.parse_args()

    if not SEMVER_RE.match(args.version):
        print(f"ERROR: version '{args.version}' must be MAJOR.MINOR.PATCH", file=sys.stderr)
        return 1
    if not args.unyank and not args.reason:
        print("ERROR: --reason is required when yanking", file=sys.stderr)
        return 1

    bridge_dir = REPO_ROOT / "bridges" / args.bridge
    if not bridge_dir.is_dir():
        print(f"ERROR: bridge '{args.bridge}' does not exist", file=sys.stderr)
        return 1

    yanks: dict = {}
    if YANKS_PATH.exists():
        yanks = json.loads(YANKS_PATH.read_text(encoding="utf-8"))

    bridge_yanks = yanks.setdefault(args.bridge, {})

    if args.unyank:
        if args.version in bridge_yanks:
            del bridge_yanks[args.version]
            if not bridge_yanks:
                del yanks[args.bridge]
            print(f"Unyanked {args.bridge} v{args.version}")
        else:
            print(f"WARN: {args.bridge} v{args.version} was not yanked", file=sys.stderr)
            return 0
    else:
        bridge_yanks[args.version] = {"yanked": True, "reason": args.reason}
        print(f"Yanked {args.bridge} v{args.version} — {args.reason}")

    if yanks:
        YANKS_PATH.write_text(json.dumps(yanks, indent=2) + "\n", encoding="utf-8")
        print(f"Updated {YANKS_PATH.name}. Commit + push to make it live, then trigger")
        print("the Regenerate Index workflow (or wait for the next publish).")
    else:
        YANKS_PATH.unlink(missing_ok=True)
        print(f"Removed {YANKS_PATH.name} (no remaining yanks). Commit + push.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
