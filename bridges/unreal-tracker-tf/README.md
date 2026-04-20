# Unreal Engine (Generic)

Tracks player state in Unreal Engine 4 and Unreal Engine 5 games using runtime introspection.

## Supported versions

Tested with UE4 and UE5 games (current release). Detects the `Engine/` directory hierarchy to identify compatible games.

## Known limitations

- Some UE games use BattlEye or Easy Anti-Cheat which may prevent attachment.
- `warn_on_unlisted_targets` is enabled — you will receive a warning when attaching to an unverified game.

## License

MIT.
