#!/usr/bin/env python3
"""Release helper for the Proximity Core bridge catalog.

Handles the full release flow for one bridge or all bridges:
  - Bump manifest.json version (optional)
  - Append CHANGELOG entry (optional)
  - Commit + push to main (if there are changes)
  - Delete + recreate a v<ver> tag (forces CI to fire; GitHub bulk-push dedup
    bug means rapid tag pushes sometimes get dropped without the recreate)
  - Push the tag individually with a short sleep so CI triggers reliably
  - Poll `gh api actions/runs` until all triggered workflows complete
  - Report the final index.json state

Usage:
    scripts/release.py <bridge-id> <version> [--bump-message MSG]
    scripts/release.py --all <version> [--bump-message MSG]
    scripts/release.py --retag-only <bridge-id> <version>

Examples:
    # Release a single bridge at v1.0.2 (manifests already at 1.0.2, changelog written)
    scripts/release.py --retag-only il2cpp-tracker-tf 1.0.2

    # Bump all 8 bridges to v1.1.0 and release in one shot
    scripts/release.py --all 1.1.0 --bump-message "Add foo feature"

Requires:
    - gh CLI authenticated as the twofault account (or with push access to twofault/*)
    - `gh auth token -u twofault` must return a valid token
    - Run from the catalog repo working directory (or its parent)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import date
from pathlib import Path

REPO = "twofault/proximity-core-catalog"
REMOTE_BASE = "https://twofault:{token}@github.com/" + REPO + ".git"
TAG_POLL_SECONDS = 10
TAG_POLL_MAX_WAIT = 600  # 10 minutes total


def run(*args: str, check: bool = True, capture: bool = False) -> str:
    """Run a subprocess; return stdout if capture, else empty string."""
    result = subprocess.run(args, check=check, text=True, capture_output=capture)
    return result.stdout if capture else ""


def gh_token_twofault() -> str:
    """Return the gh CLI token for the twofault account.

    Required because `gh auth git-credential` returns the first-stored account
    in multi-account setups, not the active one (MAINTAINER-NOTES.md §1).
    """
    return run("gh", "auth", "token", "-u", "twofault", capture=True).strip()


def gh_api(path: str, token: str) -> dict:
    """GET a GitHub API path via gh, with the twofault token."""
    out = subprocess.check_output(
        ["gh", "api", path],
        text=True,
        env={"GH_TOKEN": token, **__import__("os").environ},
    )
    return json.loads(out)


def repo_root() -> Path:
    here = Path(__file__).resolve().parent.parent
    if not (here / "bridges").exists():
        raise SystemExit(f"ERROR: no bridges/ dir at {here}; run from catalog repo")
    return here


def list_bridges(root: Path) -> list[str]:
    return sorted(p.name for p in (root / "bridges").iterdir() if p.is_dir())


def read_manifest(root: Path, bridge: str) -> dict:
    return json.loads((root / "bridges" / bridge / "manifest.json").read_text(encoding="utf-8"))


def write_manifest(root: Path, bridge: str, manifest: dict) -> None:
    path = root / "bridges" / bridge / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def bump_version(root: Path, bridge: str, version: str, message: str | None) -> bool:
    """Return True if manifest / changelog changed."""
    manifest = read_manifest(root, bridge)
    changed = False
    if manifest.get("version") != version:
        manifest["version"] = version
        write_manifest(root, bridge, manifest)
        changed = True

    changelog_path = root / "bridges" / bridge / "CHANGELOG.md"
    header = f"## v{version} ({date.today().isoformat()})"
    if changelog_path.exists():
        content = changelog_path.read_text(encoding="utf-8")
        if header not in content:
            msg_block = f"\n- {message}\n" if message else "\n- Release.\n"
            # Insert after the top "# Changelog" heading if present, else prepend
            if content.startswith("# Changelog"):
                idx = content.find("\n\n") + 2
                content = content[:idx] + header + msg_block + "\n" + content[idx:]
            else:
                content = header + msg_block + "\n" + content
            changelog_path.write_text(content, encoding="utf-8")
            changed = True
    return changed


def commit_and_push_main(root: Path, token: str, commit_message: str) -> bool:
    """Commit any staged changes + push. Returns True if something was pushed."""
    run("git", "-C", str(root), "add", "-A")
    status = run("git", "-C", str(root), "status", "--porcelain", capture=True)
    if not status.strip():
        print("  no changes to commit on main")
        return False
    run("git", "-C", str(root), "commit", "-m", commit_message)
    remote = REMOTE_BASE.format(token=token)
    run("git", "-C", str(root), "push", remote, "HEAD:main")
    print("  pushed main")
    return True


def retag_and_push(root: Path, token: str, bridge: str, version: str) -> str:
    """Delete + recreate the tag locally and on remote. Returns the tag name.

    The delete-then-push pattern works around GitHub's bulk-tag-push webhook
    dedup (MAINTAINER-NOTES.md §2) — forces a fresh webhook event for each
    tag, reliably triggering publish.yml.
    """
    tag = f"{bridge}/v{version}"
    remote = REMOTE_BASE.format(token=token)

    # Best-effort remote delete (may not exist yet)
    subprocess.run(
        ["git", "-C", str(root), "push", remote, f":refs/tags/{tag}"],
        check=False, capture_output=True,
    )
    # Local delete
    subprocess.run(
        ["git", "-C", str(root), "tag", "-d", tag],
        check=False, capture_output=True,
    )
    # Also delete any existing release + its tag via gh (cleans up release assets)
    subprocess.run(
        ["gh", "release", "delete", tag, "--cleanup-tag", "--yes", "--repo", REPO],
        check=False, capture_output=True,
        env={"GH_TOKEN": token, **__import__("os").environ},
    )

    # Create tag on current HEAD
    run("git", "-C", str(root), "tag", tag)
    # Push the tag
    run("git", "-C", str(root), "push", remote, f"refs/tags/{tag}:refs/tags/{tag}")
    print(f"  tagged + pushed {tag}")
    return tag


def wait_for_workflow(tag: str, token: str) -> dict:
    """Poll the GitHub API until a workflow run for this tag completes."""
    deadline = time.time() + TAG_POLL_MAX_WAIT
    while time.time() < deadline:
        runs = gh_api(f"repos/{REPO}/actions/runs?per_page=30&event=push", token)
        matching = [r for r in runs.get("workflow_runs", []) if r.get("head_branch") == tag]
        if matching:
            latest = matching[0]
            if latest.get("status") == "completed":
                return latest
            print(f"    [{tag}] {latest.get('status')}... waiting")
        else:
            print(f"    [{tag}] no run visible yet... waiting")
        time.sleep(TAG_POLL_SECONDS)
    raise RuntimeError(f"Timed out waiting for workflow on tag {tag}")


def verify_index(expected_bridges: list[str], expected_version: str, token: str) -> None:
    """Download index.json from main and verify it lists all expected bridges."""
    raw = subprocess.check_output(
        ["gh", "api", f"repos/{REPO}/contents/index.json?ref=main", "--jq", ".content"],
        text=True,
        env={"GH_TOKEN": token, **__import__("os").environ},
    ).strip()
    import base64
    decoded = base64.b64decode(raw).decode("utf-8")
    data = json.loads(decoded)
    print(f"\nindex.json has {len(data['bridges'])} bridges")
    by_id = {b["id"]: b for b in data["bridges"]}
    problems = []
    for bid in expected_bridges:
        if bid not in by_id:
            problems.append(f"  MISSING from index: {bid}")
            continue
        latest = by_id[bid].get("latest_version")
        if latest != expected_version:
            problems.append(
                f"  {bid}: index latest_version={latest}, expected {expected_version}"
            )
    if problems:
        print("\nISSUES FOUND:")
        for p in problems:
            print(p)
        print(
            "\nIf you see 'MISSING' or a stale latest_version, the publish.yml race "
            "(MAINTAINER-NOTES.md §3) may have lost a run. Re-poke the affected tag:\n"
            f"    scripts/release.py --retag-only <bridge-id> {expected_version}"
        )
    else:
        print(f"  all {len(expected_bridges)} bridges at v{expected_version} ✓")


def release_one(root: Path, token: str, bridge: str, version: str, message: str | None) -> str:
    print(f"\n=== releasing {bridge} v{version} ===")
    bumped = bump_version(root, bridge, version, message)
    if bumped:
        commit_and_push_main(
            root, token,
            f"release({bridge}): v{version}" + (f" — {message}" if message else ""),
        )
    return retag_and_push(root, token, bridge, version)


def cmd_single(args: argparse.Namespace) -> int:
    root = repo_root()
    token = gh_token_twofault()
    if args.bridge not in list_bridges(root):
        raise SystemExit(f"unknown bridge '{args.bridge}'. available: {list_bridges(root)}")

    tag = release_one(root, token, args.bridge, args.version, args.bump_message)

    print("\nwaiting for CI...")
    result = wait_for_workflow(tag, token)
    print(f"  workflow: {result['conclusion']}")
    verify_index([args.bridge], args.version, token)
    return 0 if result["conclusion"] == "success" else 1


def cmd_all(args: argparse.Namespace) -> int:
    root = repo_root()
    token = gh_token_twofault()
    bridges = list_bridges(root)
    print(f"releasing {len(bridges)} bridges at v{args.version}")
    tags: list[str] = []
    for bridge in bridges:
        tags.append(release_one(root, token, bridge, args.version, args.bump_message))
        # 3-second delay between tag pushes so webhooks fire individually
        # (MAINTAINER-NOTES.md §2)
        time.sleep(3)

    print("\nwaiting for all CI runs...")
    failures: list[str] = []
    for tag in tags:
        try:
            result = wait_for_workflow(tag, token)
            marker = "✓" if result["conclusion"] == "success" else "✗"
            print(f"  {marker} {tag}: {result['conclusion']}")
            if result["conclusion"] != "success":
                failures.append(tag)
        except RuntimeError as e:
            print(f"  ✗ {tag}: {e}")
            failures.append(tag)

    verify_index(bridges, args.version, token)

    if failures:
        print(
            f"\n{len(failures)} workflow(s) did not succeed. Most commonly this is the "
            "concurrent-publish race (MAINTAINER-NOTES.md §3). The release assets are "
            "usually fine; only the index.json push lost the race. Re-poke any "
            "still-missing tag with `scripts/release.py --retag-only <id> <version>`."
        )
        return 1
    return 0


def cmd_retag_only(args: argparse.Namespace) -> int:
    root = repo_root()
    token = gh_token_twofault()
    tag = retag_and_push(root, token, args.bridge, args.version)
    print("\nwaiting for CI...")
    result = wait_for_workflow(tag, token)
    print(f"  workflow: {result['conclusion']}")
    verify_index([args.bridge], args.version, token)
    return 0 if result["conclusion"] == "success" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_single = sub.add_parser("single", help="release one bridge")
    p_single.add_argument("bridge")
    p_single.add_argument("version")
    p_single.add_argument("--bump-message", default=None)

    p_all = sub.add_parser("all", help="release all bridges at the same version")
    p_all.add_argument("version")
    p_all.add_argument("--bump-message", default=None)

    p_retag = sub.add_parser("retag-only", help="re-fire CI without bumping version")
    p_retag.add_argument("bridge")
    p_retag.add_argument("version")

    args = parser.parse_args()
    if args.cmd == "single":
        return cmd_single(args)
    if args.cmd == "all":
        return cmd_all(args)
    if args.cmd == "retag-only":
        return cmd_retag_only(args)
    parser.error("unknown subcommand")
    return 1


if __name__ == "__main__":
    sys.exit(main())
