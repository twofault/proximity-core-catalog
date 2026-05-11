# Proximity Core Catalog

Catalog of bridges for [Proximity Core](https://github.com/twofault/proximity-core).

A bridge is a small Lua package that teaches Proximity Core to read positional and audio-relevant state from a specific game. Each bridge lives in `bridges/<id>/` and is released as a versioned zip via GitHub Releases.

## Using a bridge

Bridges install through Proximity Core's UI — no manual download. The app fetches [index.json](https://raw.githubusercontent.com/twofault/proximity-core-catalog/main/index.json) at startup and verifies each download by SHA-256.

## Adding a bridge

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version:

```bash
python3 scripts/new-bridge.py my-game-tracker
# edit bridges/my-game-tracker/, then:
python3 .github/scripts/validate_pr.py --bridge bridges/my-game-tracker
# open a PR
```

## Layout

```
bridges/<id>/          one bridge per directory, shipped as a zip
shared/lua/proximity/  reusable Lua modules vendored into bridges at build
.github/scripts/       validate_pr, build_zip, regenerate_index, prune_releases
.github/workflows/     validate-pr (on PR), publish (on tag), regenerate-index (after publish)
scripts/               new-bridge scaffolder, yank tool
catalog.config.json    catalog identity (repo, bot, reserved tags, retention)
index.json             generated catalog index — never hand-edit
yanks.json             yanked versions (optional; created by scripts/yank.py)
```

## Forking your own catalog

Edit `catalog.config.json` (`repo`, `bot_name`, `bot_email`). That's the only place the catalog's identity is baked in.

## License

MIT. See [LICENSE](LICENSE).
