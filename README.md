# Proximity Core Catalog

Community-maintained catalog of bridges for [Proximity Core](https://github.com/twofault/proximity-core).

A "bridge" is a small Lua package that teaches Proximity Core to read positional and
audio-relevant state from a specific game. Each bridge lives in `bridges/<id>/` and is
released as a versioned zip via GitHub Releases.

## Using a bridge

Bridges are discovered and installed automatically by Proximity Core — no manual
download needed. The app fetches `index.json` from this repo on startup.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

All bridges in this repo are licensed under the MIT License. See [CONTRIBUTING.md](CONTRIBUTING.md)
for the submission agreement.
