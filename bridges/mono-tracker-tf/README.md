# Unity Mono Tracker

Tracks player state in Unity games that use the Mono scripting backend. This is a generic bridge that works across many Unity titles.

## Supported versions

Tested with Unity 2017.x through 2021.x (Mono backend). Detects `*_Data/Managed/Assembly-CSharp.dll` and the absence of `GameAssembly.dll` to identify compatible games.

## Known limitations

- Only applies to games using the Mono scripting backend. Unity IL2CPP games require the `il2cpp-tracker` bridge instead.
- `warn_on_unlisted_targets` is enabled — you will receive a warning when attaching to an unverified game.

## License

MIT.
