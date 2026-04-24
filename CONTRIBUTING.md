# Contributing a Bridge

## License agreement

By opening a pull request to this repository you agree that your contribution is
licensed under the MIT License.

## Directory layout

A bridge lives at `bridges/<bridge-id>/` with:

- `manifest.json` (required)
- `main.lua` (required — the entry script)
- `icon.png` or `icon.svg` (required — PNG must be at least 128×128 pixels)
- `README.md` (required)
- `CHANGELOG.md` (required; at least one entry for the version you're tagging)
- `assets/` (optional — supplementary files)

Bridges run a single Lua script inside the GameLink sandbox. Injected
JavaScript (QuickJS) scripts are not supported — bridges cannot ship a
separate `.js` file, and the Lua API will reject any request to load one.

## Bridge ID rules

- Matches `^[a-z][a-z0-9-]{2,31}$` — lowercase, starts with a letter, 3–32 characters total, alphanumerics and hyphens only.
- Must be unique across the repo.
- The directory name must equal the `id` in `manifest.json`.

## `manifest.json` schema

```json
{
  "id": "your-bridge-id",
  "name": "Your Bridge Name",
  "description": "What game it reads and how.",
  "version": "1.0.0",
  "author": "your-github-handle",
  "entry": "main.lua",
  "game_engines": ["unity-mono"],
  "compatibility": {},
  "bridge_scope": "game_specific",
  "uses_blockable_apis": false,
  "warn_on_unlisted_targets": false,
  "tags": ["game-name", "engine-name"]
}
```

### Reserved tags

- `"recommended"` — applied by maintainers only. Community PRs that set this tag will be rejected by CI.

## Submission checklist

Before opening a PR:

- [ ] Bridge ID matches the regex.
- [ ] `manifest.json` validates (all required fields present).
- [ ] `README.md` describes the game, supported version range, and any known limitations.
- [ ] `CHANGELOG.md` has an entry for the version being tagged.
- [ ] `icon.png` (≥128×128) or `icon.svg` is present.
- [ ] No external HTTPS URLs in the manifest (icons must be bundled in the bridge directory).
- [ ] The `"recommended"` tag is NOT set.

## Publishing flow (maintainers only)

After a PR is merged, the maintainer tags the release as `<bridge-id>/v<semver>`:

```bash
git tag minecraft-tracker/v1.0.0
git push origin minecraft-tracker/v1.0.0
```

CI then:
1. Builds a deterministic zip of `bridges/<bridge-id>/` at that commit.
2. Creates a GitHub Release named `<bridge-id> v<version>` with the zip attached and the changelog entry as notes.
3. Regenerates `index.json` and commits it to `main`.
