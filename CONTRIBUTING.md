# Contributing

Thanks for wanting to add a bridge. The contributor experience aims to be:

- One command to scaffold a new bridge.
- One command to validate it locally — same logic the CI runs.
- A PR that gets validated automatically and merged once it passes.

## Add a bridge

```bash
python3 scripts/new-bridge.py my-game-tracker-xy
```

This creates `bridges/my-game-tracker-xy/` with a manifest, a `main.lua` stub, a placeholder icon, and a starter changelog. Edit those files.

When you think it's ready:

```bash
python3 .github/scripts/validate_pr.py --bridge bridges/my-game-tracker-xy
```

Open a PR. The same validator runs in CI and gates the merge.

## Manifest essentials

The manifest is enforced by the runtime; the validator catches anything that would silently break at install time.

| Field | Required | Notes |
|-------|----------|-------|
| `id` | yes | `^[a-z][a-z0-9-]{2,31}$`, must match the directory name |
| `name` | yes | Display name |
| `description` | yes | One-sentence summary |
| `version` | yes | Numeric semver `MAJOR.MINOR.PATCH` — no pre-release suffixes |
| `author` | yes | Your name or handle |
| `entry` | yes | Lua filename, must exist in the bridge directory |
| `gamelink_script` | no | A second Lua script loaded into Frida (in-process). Must exist or be vendored. |
| `capabilities.uses_blockable_apis` | no | Set `true` if you call `native.observe/lookup/call` — otherwise these APIs are absent. |
| `capabilities.uses_game_session` | no | Set `true` if you call `Session.*` — otherwise `Session` is absent. |
| `http_endpoints` | no | List of `https://...` URLs the bridge is allowed to fetch (glob patterns OK). Empty = no HTTP. |
| `tags` | no | Strings. **Reserved tags** are listed in `catalog.config.json` and may only be granted by maintainers — adding them to your PR will fail validation. |

The full schema lives in the runtime crate at `crates/proximity-bridge-registry/src/manifest.rs`. The validator is the practical contract — if `python3 .github/scripts/validate_pr.py --bridge ...` passes, the PR will pass CI.

## Bridge lifecycle

Your `main.lua` implements three functions:

```lua
function init()
    -- runs once, as a coroutine. Use Bridge.setProgress() for slow setup.
end

function update(dt)
    -- runs each frame. Write camera/listener/speaker state to GameStore.
end

-- function dispose()
--     -- optional. Runtime auto-cleans Gamelink + HTTP + observers.
--     -- Use only for final user-facing actions (e.g. clearing UI state).
-- end
```

API reference lives in the Proximity Core repo under `.claude/rules/lua-scripts.md`. Public APIs your bridge has access to:

- `GameStore.*` — local player position, orientation, level, surroundings, sound profile.
- `Gamelink.*` — process memory APIs (requires `capabilities.uses_blockable_apis`).
- `Session.*` — game-session discovery (requires `capabilities.uses_game_session`).
- `Http.*` — HTTPS only, must match a declared `http_endpoints` glob.
- `Capture` / `CV` / `OCR` / `Resource` — for vision-based bridges.

## Shared modules

If you need a utility module that several bridges would copy, propose it at `shared/lua/proximity/<name>.lua`. Bridges declare what they vendor in `.catalog-vendor.json`:

```json
{
  "lua": {
    "shared/lua/proximity/net_id_capture.lua": "net_id_capture.lua"
  }
}
```

At build time the shared file is copied into the zip at the destination path. The bridge's `main.lua` then `Gamelink.loadScript("net_id_capture.lua", ...)` it like any local file.

Changes to `shared/**` automatically re-validate every bridge that vendors the file.

## Releasing (maintainers only)

A merged PR doesn't publish a release. Tagging does:

```bash
git tag my-game-tracker-xy/v0.1.0
git push origin my-game-tracker-xy/v0.1.0
```

The Publish workflow builds the zip, computes the SHA-256 from the zip bytes, and creates a GitHub Release with the asset. Once it completes, the Regenerate Index workflow rebuilds `index.json` and prunes old releases (keeping `release_keep_count` from `catalog.config.json`, default 10).

## Yanking a bad release

```bash
python3 scripts/yank.py my-game-tracker-xy 0.1.0 --reason "crashes Game Pass build"
git commit -am "yank: my-game-tracker-xy v0.1.0"
git push
```

Yanking writes `yanks.json` and triggers an index regeneration. The app filters yanked versions out of update candidates; users with the bad version installed see the yank flag in the UI and are prompted to upgrade.

## Forking your own catalog

Edit `catalog.config.json` — `repo`, `bot_name`, `bot_email`. That's the only file with the catalog's identity baked in. The workflows and scripts read everything else from there.

## Style

- Lua: 4-space indent, `snake_case` for locals, no global state unless absolutely necessary.
- Comments explain *why* something is non-obvious, not *what* the code does — well-named identifiers handle that.
- No external CDN URLs in the manifest; bundle icons + assets.
- Keep the manifest's `description` to one sentence.
