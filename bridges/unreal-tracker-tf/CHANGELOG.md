# Changelog

## v1.0.6 (2026-05-01)
- Migrate to GameStore Lua API + min_app_version 0.2.0

## v1.0.5 (2026-04-30)
- Fix pollAttach nil-deref crash on Frida-side attach failure

## v1.0.4 (2026-04-30)
- Migrate bridge Lua to new tuple-return Gamelink API (fixes attach retry storm)

## v1.0.3 (2026-04-30)
- Migrate manifests to capabilities block + http_endpoints (Phase 4.1)

## v1.0.2 (2026-04-22)
- Bump engine tick to 60Hz + clean up bridge scripts

## v1.0.1 (2026-04-22)

- Rebrand: all user-facing "Frida" references now say "GameLink" to match the Lua API.

## v1.0.0 (2026-04-18)

Initial public release.
- Uses Gamelink Lua API (formerly Frida).
