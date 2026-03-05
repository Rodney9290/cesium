# Known Caveats

Cesium's analysis is based on packet captures, which have inherent
limitations. Every diagnosis should be interpreted with these in mind.

## 1. Capture Point Matters

Where the capture was taken affects what you see:

- **Client-side capture**: you see the client's retransmissions but may
  miss server-side issues
- **Server-side capture**: the reverse
- **Mirror/SPAN port**: may introduce reordering or drops of its own

## 2. TCP Offload

Modern NICs offload segmentation (TSO/GSO) and checksum computation.
Captures taken on the sending host may show:

- Oversized segments (larger than MTU)
- Invalid checksums (computed by the NIC, not visible to the capture)

These are normal and not actual errors.

## 3. Encrypted Traffic

TLS-encrypted connections only show handshake metadata (SNI, cipher
negotiation). Application-layer content is not visible without decryption
keys.

## 4. Incomplete Captures

If a capture starts mid-connection, Cesium may not see the original
handshake. This can lead to:

- Missing RTT estimates
- "Incomplete handshake" false positives
- Missing DNS resolution events

## 5. Clock Precision

Timestamp precision depends on the capture tool and OS. Sub-millisecond
timing comparisons should be treated as estimates.
