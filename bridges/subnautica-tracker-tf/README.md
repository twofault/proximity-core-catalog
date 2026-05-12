# Subnautica Tracker

Tracks player camera and surroundings in Subnautica (Unity Mono). Drives `underwater`, `radio_access`, `room_size`, and `reverb` so audio reacts to the player being submerged, in a vehicle/sub, or in a confined air pocket.

## Supported versions

Tested with current Subnautica retail build (Epic Games Store). Locates the `Player` singleton by memory-scanning for the Player MonoClass — first attach takes ~60 s, subsequent attaches in the same process are instant (cached).

## Known limitations

- Subnautica only (rejects IL2CPP builds via the `GameAssembly.dll` forbid rule).
- First attach scan is slow (~60 s).
- Underwater depth ramp uses camera Y vs sea level (Subnautica's ocean is at y=0); does not account for Precursor pockets below sea level — those are handled by the `precursorOutOfWater` air-pocket gate instead.

## TODO

- Continuous `room_size` based on actual interior volume rather than fixed values per vehicle.
- Per-distance `radio_interference` so distant radio voice gets atmospheric noise.
- Recompute Player singleton on save reload (currently relies on vtable invalidation to re-discover).

## License

MIT.
