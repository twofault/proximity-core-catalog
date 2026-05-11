#!/usr/bin/env python3
"""Scaffold a new bridge under bridges/<id>/.

Usage:
    python3 scripts/new-bridge.py <id> [--author NAME] [--name "Display Name"]

Produces:
    bridges/<id>/manifest.json   minimal valid manifest (version 0.1.0)
    bridges/<id>/main.lua        init/update/dispose stubs
    bridges/<id>/README.md       short template
    bridges/<id>/CHANGELOG.md    v0.1.0 entry
    bridges/<id>/icon.png        128x128 placeholder

The id must match `^[a-z][a-z0-9-]{2,31}$` and not collide with an
existing bridge.
"""
import argparse
import json
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,31}$")


def git_user_name() -> str:
    try:
        return subprocess.check_output(["git", "config", "user.name"], text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "anonymous"


def placeholder_png(dest: Path) -> None:
    """Write a 128x128 single-color PNG without pulling in PIL."""
    width = height = 128
    raw = b"".join(b"\x00" + b"\x80\x80\x80" * width for _ in range(height))  # mid-grey

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    dest.write_bytes(png)


def write_files(bridge_dir: Path, bid: str, display_name: str, author: str) -> None:
    bridge_dir.mkdir(parents=True)

    manifest = {
        "id": bid,
        "name": display_name,
        "description": "TODO — what does this bridge track?",
        "version": "0.1.0",
        "author": author,
        "entry": "main.lua",
        "game_engines": [],
        "compatibility": {
            "platforms": ["windows"],
            "executable": {"any_of": [{"exact": "TODO.exe"}]},
        },
        "capabilities": {
            "uses_blockable_apis": False,
            "uses_game_session": False,
        },
        "http_endpoints": [],
        "warn_on_unlisted_targets": False,
        "bridge_scope": "game_specific",
        "tags": ["experimental"],
    }
    (bridge_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    (bridge_dir / "main.lua").write_text(
        f"""-- {display_name} bridge.
-- Implements the host contract: init(), update(dt), and optionally dispose().

function init()
    -- One-time setup. Runs as a coroutine; use Bridge.setProgress() for slow work.
    Bridge.setProgress("Initializing {display_name}", 1.0)
end

function update(dt)
    -- Called every frame. Write camera/listener/speaker state to GameStore.
    -- Example:
    --   GameStore.setCameraPosition(x, y, z)
    --   GameStore.setCameraOrientation(pitch, yaw, roll)
end

-- function dispose()
--     -- Optional. Runtime auto-cleans Gamelink, HTTP, observers.
--     -- Use this only for final user-level actions (e.g. clearing UI state).
-- end
""",
        encoding="utf-8",
    )

    (bridge_dir / "README.md").write_text(
        f"""# {display_name}

TODO — what game does this cover, what does it track, any caveats?

## Compatibility

- Platforms: Windows
- Target: TODO
""",
        encoding="utf-8",
    )

    (bridge_dir / "CHANGELOG.md").write_text(
        "# Changelog\n\n## v0.1.0\n- Initial release.\n",
        encoding="utf-8",
    )

    placeholder_png(bridge_dir / "icon.png")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("id", help="Bridge id (e.g. my-game-tracker-xy)")
    parser.add_argument("--author", help="Author name (defaults to git user.name)")
    parser.add_argument("--name", help="Display name (defaults to id Title Case)")
    args = parser.parse_args()

    if not ID_RE.match(args.id):
        print(f"ERROR: id '{args.id}' must match ^[a-z][a-z0-9-]{{2,31}}$", file=sys.stderr)
        return 1

    bridge_dir = REPO_ROOT / "bridges" / args.id
    if bridge_dir.exists():
        print(f"ERROR: {bridge_dir} already exists", file=sys.stderr)
        return 1

    author = args.author or git_user_name()
    display_name = args.name or args.id.replace("-", " ").title()
    write_files(bridge_dir, args.id, display_name, author)

    print(f"Scaffolded {bridge_dir}")
    print()
    print("Next steps:")
    print(f"  1. Edit bridges/{args.id}/manifest.json (description, compatibility, tags)")
    print(f"  2. Implement bridges/{args.id}/main.lua")
    print(f"  3. Replace bridges/{args.id}/icon.png (>=128x128)")
    print(f"  4. Validate: python3 .github/scripts/validate_pr.py --bridge bridges/{args.id}")
    print(f"  5. Open a PR.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
