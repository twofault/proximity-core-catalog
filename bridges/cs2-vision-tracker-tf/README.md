# Counter-Strike 2 (Vision)

Tracks player state in Counter-Strike 2 using computer vision against the in-game minimap. No memory reading or Frida injection required.

## Supported versions

Tested with CS2 1.x (current live release). Vision-based detection should remain stable across game updates that do not significantly redesign the minimap.

## Known limitations

- Requires the minimap to be visible on screen.
- Accuracy depends on minimap scale and map selection — custom workshop maps may not match reference templates.

## License

MIT.
