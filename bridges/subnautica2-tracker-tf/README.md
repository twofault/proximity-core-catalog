# Subnautica 2 Tracker

Tracks player camera and surroundings in Subnautica 2 (UE5 early access). Drives `underwater`, `radio_access`, `room_size`, and `reverb` so audio reacts to the player being submerged or piloting a vehicle.

## Supported versions

Tested with Subnautica 2 early access (WinGDK build, ~204 MB exe). First attach takes ~80 s for the UE introspection pass; subsequent attaches in the same process are faster via the bridge's offset cache.

## How it works

State is read by UE reflection rather than hardcoded offsets. The agent resolves a small number of fields on the live pawn class:

- `CharacterMovement.MovementMode` (UE built-in) — drives underwater via `MOVE_Swimming = 4`.
- A vehicle-reference `ObjectProperty` on the pawn — populated when the player pilots e.g. a Tadpole without UE re-possession.
- The pawn's own class name — vehicle pawns (Seatruck, Hoverbike, Prawn, etc.) are caught here.

When the player enters a vehicle that does re-possess the pawn, UE swaps the class and the agent re-probes automatically.

## Known limitations

- Early access game, class names / property names may shift across builds. The CMC lookup is substring-tolerant; vehicle tuning is class-name based with a generic fallback. New vehicles can be added in `SN2_VEHICLE_TUNING` (main.lua).
- Habitat ("in base") detection is **not implemented**. Earlier versions used `InBaseGracePeriod` / `CurrentOxygenator` / `bInBaseReplication`, but `InBaseGracePeriod` reads the Class Default Object value (0.15) even outside any base, and the other two stayed false in every tested scene. Net effect today: when the player walks into a habitat the CMC drops out of MOVE_Swimming, so audio correctly stops applying the underwater filter — but the habitat doesn't get its own reverb/room profile.

## Multiplayer / game session

The bridge loads the shared `net_id_capture.lua` subscript to surface a `session_id` for auto-discovery. Subnautica 2 uses Epic Online Services (EOS) for networking — specifically the EOS_P2P transport, not EOS Sessions or EOS Lobby — so detection is observer-based and only fires once at least one other player is connected and packets are flowing. Concretely:

- The bridge hooks `EOS_P2P_ReceivePacket` and `EOS_P2P_SendPacket`. Every successful packet carries an `EOS_P2P_SocketId` whose `SocketName` is by convention derived from the shared lobby id, so all peers see the same value.
- When the bridge captures that value it emits a `session_id` of `eos_p2p:<SocketName>`. Proximity then uses the hash of that as the auto-discovery beacon.
- **Limitation**: alone-in-a-session produces no `session_id`. SN2 caches its EOS lobby handle at code-generation time and never calls any user-facing Lobby getter again, so observing those APIs post-attach catches nothing. The in-game invite code (`####-####`) is constructed on demand for display and isn't stored as a plain string anywhere we could memory-scan for it.
- **Net effect**: once a friend joins via your code, Proximity will start auto-discovering peers in the same SN2 session. By yourself, no game-session beacon is published.

## TODO

- Habitat detection: find a reliable in-base signal (likely an overlap-volume hit or a live grace-period timer that's actually 0 outside any base) to drive a habitat reverb profile.
- Verify pawn class names for all vehicle types (Seatruck variants, Hoverbike, Prawn).
- Continuous depth from a dedicated property if SN2 exposes one (current path computes depth from camera Y).
- Pre-peer session detection: if SN2 exposes its lobby id through some other observable surface (UI-bound UE property, a custom UnknownWorlds backend that ships its session id over HTTP, etc.) wire that up so the beacon publishes the moment the host generates the code.

## License

MIT.
