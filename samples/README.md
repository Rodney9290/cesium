# Sample Captures

Place `.pcap` or `.pcapng` files here for testing.

## Recommended test captures

Download these from the [Wireshark Sample Captures wiki](https://wiki.wireshark.org/SampleCaptures):

1. **DNS** - `dns.cap` — basic DNS queries and responses
2. **HTTP** - `http.cap` — simple HTTP GET/response traffic
3. **TLS** - `tls12-dsb.pcapng` — TLS 1.2 handshake with decryption keys

You can also generate your own with:

```sh
# Capture 100 packets on the default interface
tshark -c 100 -w samples/my-capture.pcapng
```
