# Maintainer Notes — proximity-core-catalog

Operational quirks encountered while maintaining this repo. Read before doing
any bulk publishing operation (tagging, renaming bridges, mass-deleting
releases) to avoid wasted time and misleading CI output.

Keep this file updated as new quirks are discovered.

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
