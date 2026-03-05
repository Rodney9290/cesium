# How Cesium Decodes Packets

Cesium does **not** implement its own protocol parser. All packet decoding is
performed by [TShark](https://www.wireshark.org/docs/man-pages/tshark.html),
the command-line interface to Wireshark's dissection engine.

## Why TShark?

- Uses the same decoding engine as Wireshark (identical dissection results)
- Supports 3,000+ protocols out of the box
- Actively maintained by the Wireshark community
- Structured output via `-T ek` (newline-delimited JSON)

## Duplicate-key caveat

Some protocol dissections produce JSON with duplicate keys. Cesium uses
TShark's `--no-duplicate-keys` flag to avoid parsing issues. See:
[Wireshark JSON export has multiple keys with identical names](https://www.reddit.com/r/wireshark/comments/1gkvu2l/)

## References

- [TShark man page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Wireshark export formats](https://wireshark.marwan.ma/docs/wsug_html_chunked/ChIOExportSection.html)
