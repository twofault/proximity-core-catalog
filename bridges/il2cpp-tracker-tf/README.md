# Unity IL2CPP Tracker

Tracks player state in Unity games that use the IL2CPP scripting backend. This is a generic bridge that works across many Unity titles.

## Supported versions

Tested with Unity 2019.x through 6000.x (IL2CPP backend). Detects the presence of `GameAssembly.dll` to identify compatible games.

## Known limitations

- Some Unity games use anti-cheat that may conflict with GameLink-based memory reading.
- `warn_on_unlisted_targets` is enabled — you will receive a warning when attaching to an unverified game.

## License

MIT.
