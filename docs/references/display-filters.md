# How Filters Work

Cesium's natural-language filter feature translates user queries into
Wireshark display filter expressions.

## Wireshark Display Filter System

Display filters use a field-based syntax. Every protocol field decoded by
Wireshark has a canonical name (e.g., `tcp.flags.syn`, `dns.qry.name`,
`http.request.method`).

### Examples

| User query | Wireshark filter |
|---|---|
| "show DNS problems" | `dns.flags.rcode != 0` |
| "show failed handshakes" | `tcp.flags.syn == 1 && tcp.flags.ack == 0 && !tcp.analysis.initial_rtt` |
| "show retransmissions" | `tcp.analysis.retransmission` |
| "show only one device" | `ip.addr == <device_ip>` |
| "show slow responses" | `http.time > 1` |

## Why we show the real filter

Cesium always displays the underlying Wireshark filter expression alongside
the natural-language query. This helps beginners learn the actual syntax
without being blocked by it.

## References

- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [wireshark-filter(4) Manual Page](https://www.wireshark.org/docs/man-pages/wireshark-filter.html)
- [Building Display Filter Expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
