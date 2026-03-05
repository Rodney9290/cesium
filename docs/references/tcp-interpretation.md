# Why We Interpret TCP Retransmissions This Way

## TCP Reliability Model

TCP guarantees reliable delivery through sequence numbers and
acknowledgments (RFC 793, Section 3.3). When a sender transmits a segment,
it starts a retransmission timer. If no ACK arrives before the timer
expires (the Retransmission Timeout / RTO), the sender retransmits.

### What Cesium reports

| Observation | Interpretation | Confidence |
|---|---|---|
| Duplicate sequence number after timeout | Likely packet loss | Medium |
| Duplicate sequence number with duplicate ACKs | Fast retransmission (congestion signal) | High |
| SYN without SYN/ACK | Connection refused or filtered | High |
| RST received | Abrupt connection termination | High |

### Why "medium" confidence for retransmissions?

A retransmission in a capture does not always mean the original packet was
lost on the wire. Possible alternatives:

- **Capture-point artifact**: if capturing at the sender, you may see the
  retransmission but the original may have arrived at the receiver fine
  (delayed ACK)
- **Spurious retransmission**: RTO can fire early due to RTT variance
- **TCP offload**: NIC offload features can produce artifacts in captures

Cesium always notes these caveats alongside findings.

## References

- [RFC 793 — Transmission Control Protocol](https://datatracker.ietf.org/doc/html/rfc793) (Section 3.3: Sequence Numbers, Section 3.7: Data Communication)
- [RFC 6298 — Computing TCP's Retransmission Timer](https://datatracker.ietf.org/doc/html/rfc6298)
- [RFC 5681 — TCP Congestion Control](https://datatracker.ietf.org/doc/html/rfc5681) (Fast Retransmit, Section 3.2)
