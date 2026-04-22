# Maintainer Notes — proximity-core-catalog

Operational notes + release workflows for this repo.

**Current status: pre-public-release alpha.** All bridges are marked
`experimental`. Pushing rough changes is fine — we prefer iteration over
gatekeeping right now. The stricter review culture kicks in post-launch.

---

## Pre-launch posture (read this first)

- The app is **not yet shipped publicly**. No users depend on this catalog yet.
- Every bridge carries the `"experimental"` tag — users see a warning badge in the app.
- Push freely. Test after, not before. Rollback is cheap (just re-tag).
- Don't over-think version bumps. Patch-bump (`1.0.1` → `1.0.2`) for anything;
  don't use semver discipline until post-launch.
- If a release goes wrong, just re-release. You can't break a user base that doesn't exist yet.

This posture will flip at launch. When it does, update this section and add
a gating checklist (staging repo, manual QA, review approvals).

---

## Directory orientation

**Do all catalog work in `.catalog-repo-work/`.** It's the clone of
`github.com/twofault/proximity-core-catalog`; its `origin` points at the real
catalog. Tags, pushes, and `scripts/release.py` all run from here.

Ignore `.catalog-repo-staging/` — unrelated scratch directory from the initial
bootstrap. Nothing there is auto-ported anywhere. If you accidentally edit
bridge files there, copy them into `.catalog-repo-work/bridges/<id>-tf/`
manually before releasing.

Bridge directory names use the `-tf` suffix (e.g., `il2cpp-tracker-tf`). Don't
drop the suffix when editing paths or tag names.

---

## Release workflows

Every git tag of the form `<bridge-id>/v<major>.<minor>.<patch>` triggers
`.github/workflows/publish.yml`, which:

1. Zips `bridges/<bridge-id>/` deterministically
2. Creates a GitHub Release with the zip attached and the CHANGELOG entry as notes
3. Regenerates `index.json` from the full release list and pushes it to `main`

Prerequisites: `cd .catalog-repo-work`, `gh` logged in as `twofault`,
Python 3 on PATH.

### Decision guide — common situations

**"I have bridge code changes to ship."**
→ Bump patch version (whatever's current + 1), pick a commit message describing
the change, run `scripts/release.py all <version> --bump-message "<msg>"`. Done.

**"There are already local commits in `.catalog-repo-work` ahead of `origin/main`."**
→ Pre-launch, this is fine. Just push them as part of the next release. The
`scripts/release.py` flow pushes `HEAD` to `main` before tagging, so existing
local commits go along for the ride. Don't split them into separate pushes
for "hygiene" unless they're actually broken.

**"Manifests are already bumped locally but not pushed yet."**
→ Run `scripts/release.py retag-only <bridge-id> <version>` — it skips the
bump step and just pushes + re-tags. Or if all 8 manifests are already
bumped, do the token-in-URL push for `HEAD:main` manually, then loop
`retag-only` over each bridge.

**"I'm nervous because this is a `twofault` org repo."**
→ Pre-launch, don't be. You can't break a user base that doesn't exist yet.
If something lands wrong, re-tag with `retag-only`. Worst case you delete the
whole catalog and re-publish everything — takes 5 minutes with `scripts/release.py all`.

**"Three workflow runs show 'failure' after an `all` release."**
→ That's the index-push race (§3 below). The zips + release entries all
landed fine; only the index regen push for THOSE runs lost the race. Some
LATER run regenerated the index with all entries present. Verify with:
```bash
curl -sL "https://raw.githubusercontent.com/twofault/proximity-core-catalog/main/index.json?t=$(date +%s)" | python3 -m json.tool | grep latest_version
```
If a bridge is missing from the index or stuck at an older version, re-poke
it with `scripts/release.py retag-only <bridge-id> <version>`.

---

### Easy path — use `scripts/release.py`

This script handles the auth workarounds, tag-push deduplication, and CI
polling automatically. Pick a subcommand:

**Release one bridge at a new version** (bumps manifest + changelog + tags + polls CI):

```bash
python3 scripts/release.py single il2cpp-tracker-tf 1.0.2 \
    --bump-message "Fix crash on Unity 2023.x startup"
```

**Release ALL bridges at the same version** (mass rebrand, API migration, etc.):

```bash
python3 scripts/release.py all 1.1.0 \
    --bump-message "Migrate to GameLink API"
```

**Re-fire CI for an already-tagged version** (useful if the concurrent-publish
race dropped an index regen):

```bash
python3 scripts/release.py retag-only il2cpp-tracker-tf 1.0.2
```

The script auto-retries the auth pattern (token-in-URL push) and polls
`gh api actions/runs` until workflows complete, then verifies `index.json`
contains the expected versions.

### Manual path — if you want to understand every step

1. **Edit the bridge's source files** under `bridges/<bridge-id>/`.
2. **Bump the version** in `bridges/<bridge-id>/manifest.json`.
3. **Add a CHANGELOG entry**:
    ```markdown
    ## v1.0.2 (YYYY-MM-DD)

    - What changed.
    ```
4. **Commit + push main**:
    ```bash
    git add -A
    git commit -m "release(<bridge-id>): v1.0.2 — <summary>"
    TOKEN=$(gh auth token -u twofault)
    git push "https://twofault:${TOKEN}@github.com/twofault/proximity-core-catalog.git" HEAD:main
    ```
5. **Delete any pre-existing tag/release** (idempotent; prevents stale tag
   pointing at an older commit):
    ```bash
    GH_TOKEN=$(gh auth token -u twofault) \
        gh release delete "<bridge-id>/v1.0.2" --cleanup-tag --yes \
        --repo twofault/proximity-core-catalog
    ```
6. **Tag the commit and push the tag individually** (see §2 for why "individually"):
    ```bash
    git tag "<bridge-id>/v1.0.2"
    git push "https://twofault:${TOKEN}@github.com/twofault/proximity-core-catalog.git" \
        "refs/tags/<bridge-id>/v1.0.2:refs/tags/<bridge-id>/v1.0.2"
    ```
7. **Watch CI**:
    ```bash
    GH_TOKEN=$(gh auth token -u twofault) \
        gh run list --repo twofault/proximity-core-catalog --limit 5
    ```
8. **Verify the index**:
    ```bash
    curl -sL "https://raw.githubusercontent.com/twofault/proximity-core-catalog/main/index.json?t=$(date +%s)" \
        | python3 -m json.tool | grep -A2 '"<bridge-id>"'
    ```

### AI agent task templates

Copy-paste these into a sub-agent prompt for common operations:

**Task: Release a single bridge at a new version**

> Release `<bridge-id>` at v`<version>`. Source edits have already been
> made to the bridge files.
>
> Run `python3 scripts/release.py single <bridge-id> <version> --bump-message "<msg>"`
> from the catalog repo working directory. Wait for it to finish. If it
> exits non-zero because the concurrent-publish race (MAINTAINER-NOTES.md §3)
> dropped the index regen, re-run with `retag-only` for that one bridge.
> Report the final `index.json` state for `<bridge-id>`.

**Task: Release all bridges at the same version**

> Release ALL bridges in the catalog at v`<version>`. Source edits have
> already been made across all `bridges/*/` directories.
>
> Run `python3 scripts/release.py all <version> --bump-message "<msg>"`
> from the catalog repo working directory. Each bridge's manifest will be
> bumped, a CHANGELOG entry added, and a tag pushed with a 3-second delay
> between pushes. The script polls CI for all tags.
>
> Expect 0-3 "failure" markers per MAINTAINER-NOTES.md §3 — the release
> zips + entries all land correctly; only the `index.json` regen push
> can lose the race. Re-poke any missing bridges with the `retag-only`
> subcommand. Verify `index.json` shows `latest_version: "<version>"`
> for every bridge at the end.

**Task: Bulk add a bridge to the recommended tag**

> Maintainers-only operation — `"recommended"` is reserved (CI rejects
> PRs that add it). So it has to be a direct push to `main` + an index
> regen.
>
> 1. Edit `bridges/<bridge-id>/manifest.json` and add `"recommended"` to
>    the `tags` array.
> 2. Commit + push main via the token-in-URL pattern (see §1 below).
> 3. The index won't auto-regen for a tag-less push — either re-fire a
>    non-version-bumping release with `retag-only`, OR wait for the next
>    regular release cycle. For immediate effect, use `retag-only` on the
>    bridge's existing version.

---

## 1. GitHub CLI multi-account auth confusion

**Symptom:** `git push` fails with `403 Permission denied to <wrong-user>` even
though `gh auth status` shows the correct account as "Active".

**Cause:** `gh auth git-credential get` (the command git calls when
`credential.https://github.com.helper` is set to `gh auth git-credential`)
returns the *first-matched* stored account, **not the active one**. If multiple
accounts are logged in, git silently authenticates as the wrong user.

Verify which creds gh is actually returning:

```bash
echo -e "protocol=https\nhost=github.com\n" | gh auth git-credential get
```

**Safe workaround — push with an explicit per-user token in the URL:**

```bash
TOKEN=$(gh auth token -u <correct-account>)
git push "https://<correct-account>:${TOKEN}@github.com/<org>/<repo>.git" HEAD:main
# For tags:
git push "https://<correct-account>:${TOKEN}@github.com/<org>/<repo>.git" refs/tags/<tag>:refs/tags/<tag>
```

**For `gh api` / `gh release` commands** — pass the token via env var:

```bash
GH_TOKEN=$(gh auth token -u <correct-account>) gh release delete ...
```

Without `GH_TOKEN`, `gh` picks the active account, but those commands that
wrap git operations (e.g. `gh release upload`) may still hit the credential
helper bug.

**Permanent fix:** log out the other account entirely (`gh auth logout
--hostname github.com --user <wrong-account>`) if you won't need it again
soon.

---

## 2. Bulk tag push deduplicates workflow triggers

**Symptom:** Pushed 8 tags with `git push origin --tags`. Expected 8 workflow
runs. Got zero.

**Cause:** When many tags are pushed in a single atomic `push` operation,
GitHub sometimes coalesces or drops the per-tag `push` webhook events, so
`on: push: tags: *` workflows fire for only a subset (or none). Reproducible
enough that we treat it as a known quirk, not a one-off.

**Safe workaround — push tags one-by-one with a short delay. Force-refresh
each with a delete+re-push pattern so GitHub definitely re-registers the
event:**

```bash
for tag in tag-a/v1 tag-b/v1 tag-c/v1; do
  git push "$REMOTE" ":refs/tags/$tag"                        # delete remote
  sleep 1
  git push "$REMOTE" "refs/tags/$tag:refs/tags/$tag"          # push fresh
  sleep 2                                                     # let webhook fire
done
```

This produces one workflow run per tag, every time.

**If you only need ONE tag re-triggered** (e.g. a previously-failed run):
delete + re-push that single tag. Same pattern, same reliability.

---

## 3. Concurrent `publish.yml` races on index.json push

**Symptom:** One of eight bulk-tagged workflow runs shows "failed" at the
"Commit + push index" step with:

```
error: failed to push some refs to '...proximity-core-catalog'
##[error]Process completed with exit code 1.
```

**Cause:** `publish.yml` finishes each release by regenerating `index.json`
and pushing to `main`. When multiple workflows run concurrently (one per
tag), they all race to `git push origin main` — one wins, the rest see their
push rejected because `main` moved underneath them.

**Impact is cosmetic, not functional:**
- Each workflow still created its own GitHub Release + zip asset successfully.
- The last workflow to finish regenerates `index.json` **including all
  existing releases** (the script iterates `gh release list`). So the
  winning `index.json` has every bridge, even those whose workflows "failed".
- The "failure" marker on the workflow itself is misleading — that specific
  run's index push lost the race, but the state is still consistent.

**When it matters:** if you're checking CI status as a green/red signal for
"did the release complete", you'll get false negatives. Look at the actual
release list and `index.json` content to verify.

**Long-term fix** (not yet implemented): add a repo-wide concurrency group
to the index-push step so only one workflow at a time can push:

```yaml
# inside publish.yml, around the "Commit + push index" step
concurrency:
  group: publish-index
  cancel-in-progress: false
```

This serializes the index-push phase across all bridge tags, at the cost of
longer total wall-time when many tags land at once. Apply when the false-
negative noise becomes a real problem.

---

## 4. `git push --tags` also pushes deleted local tags back up

**Symptom:** Renamed a bridge (e.g. `foo-bar` → `foo-bar-tf`). Deleted the
old GitHub release + tag. Ran `git push --tags` to push the new tags. The
old tag came back.

**Cause:** `git push --tags` pushes *all* local tags the remote doesn't have.
The local `foo-bar/v1.0.0` tag still existed (just deleting a remote tag
doesn't affect local refs). Git happily re-created it on the remote.

**Safe workaround — delete the old tag locally before pushing tags:**

```bash
git tag -d foo-bar/v1.0.0      # delete locally
TOKEN=$(gh auth token -u twofault)
REMOTE="https://twofault:${TOKEN}@github.com/twofault/proximity-core-catalog.git"
git push "$REMOTE" ":refs/tags/foo-bar/v1.0.0"   # delete on remote
```

Or: don't use `--tags`. Push specific tag refs explicitly:

```bash
git push "$REMOTE" "refs/tags/foo-bar-tf/v1.0.0"
```

---

## 5. `logs/user_prompt_submit.json` leaks from the outer project

**Symptom:** `git add -A` inside `.catalog-repo-work/` captures a `logs/`
directory that you didn't create. The Proximity Core app's
`.claude/hooks/user_prompt_submit.py` hook writes its log to a relative
`logs/` path from the shell's cwd; if the shell happens to be inside the
catalog clone, the hook writes into the catalog repo.

**Fix applied in .gitignore:** `logs/` added to the catalog repo's
.gitignore. If it shows up again anyway, unstage and delete:

```bash
git rm -r --cached logs/
rm -rf logs/
```

**Prevention:** keep the catalog repo clone in its own parent directory
outside Proximity Core's checkout if possible. When you have to work inside
the Proximity Core tree, watch `git status` output before `git add -A`.
