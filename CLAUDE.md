# hoptun

UDP tunnel for connection stability in roaming and lossy networks. The client hops to a new server
host:port (and a fresh local source port, hence a fresh NAT mapping) every second, so buggy NATs
that drop or time out long-lived flows never get a long-lived flow to break. No handshake, no
session state: "connectionless connections". Exactly one client and one server.

```
app ⇄ client [listen] ⇄ (hopping UDP) ⇄ server [hosts × ports] ⇄ [target]
```

## Layout
- `main.go`: config, schedule, server, client.
- `batch.go`: batched UDP I/O (`pump`): recvmmsg/sendmmsg, GRO/GSO, socket tuning. Linux-only.
- Only dependency: `golang.org/x/net` (`ipv6.PacketConn` batch API). It is pinned at v0.44.0 because newer
  versions require Go 1.26. Keep `go 1.24` in go.mod.
- `main_test.go`: loopback end-to-end test (IPv4 + IPv6, asserts echo delivery and observed hopping).
- `hop.example.json`: sample shared config.

## Usage
```
hoptun server -c hop.json
hoptun client -c hop.json
```
The **same config file** is copied verbatim to both sides; mismatched schedules silently break the
tunnel. Each side logs `schedule fingerprint XXXXXXXX` at startup, so compare them.

```json
{
  "hosts":  ["2001:db8::1", "203.0.113.5"],
  "ports":  [[40000, 40015]],
  "key":    "shared",
  "target": "127.0.0.1:9000",
  "listen": "[::1]:5000"
}
```
- `hosts` × `ports` (inclusive ranges) form the pair list, in file order. IPv4/IPv6/zoned addresses work.
- `key` perturbs the schedule and keys the obfuscation. It is **not** a security measure.
- `target` is used by the server only (the forward destination); `listen` by the client only (where the local app sends).

## How it works
- **Schedule:** `HP(t) = pairs[FNV-1a(key ‖ uint64be(t)) % len(pairs)]`, `t` = UTC unix seconds. Both sides
  must be time-synced to about ±1 minute.
- **Server:** at each minute boundary it binds every pair in `{HP(t) | t ∈ [minute−60s, minute+120s)}` and
  closes the rest. Every datagram on any open socket is forwarded to `target`, with no filtering
  for a wrong host:port. Replies from `target` go out of the socket the **latest** datagram
  arrived on, to the peer it came from (`srvLast`). Host IPs must be configured on the server's
  interfaces.
- **Obfuscation:** every datagram on the wire (data, probes, ACKs) is XORed with a per-pair keystream:
  AES-128-CTR, key `SHA-256(key ‖ 0x00 ‖ "host:port")[:16]`, fixed zero IV, computed once per socket (64 KiB).
  Every datagram (each GRO segment too) starts at keystream offset 0. Zero bytes added. It is meant only to defeat
  DPI that matches inner-protocol headers. Because the keystream repeats, XORing two packets from the same pair
  cancels it, and packet lengths are unchanged.
- **Probes:** a probe is a datagram of exactly 32 zero bytes (before obfuscation). The server never forwards a probe and never updates
  `srvLast` for one. It answers with the same 32 zero bytes three times, 1 s apart, from the socket the probe
  arrived on.
- **Client:** keeps one channel (socket + state) per pair. Each second `T`:
  1. It probes slot `HP(T+5)` from a fresh socket, which means a fresh NAT mapping. It skips the probe and reuses
     the existing socket if that socket got a datagram in the last 5 s (or has a probe still pending) and will
     be younger than `maxAge` (10 s) when its slot comes. On startup it probes every slot from `T` to `T+5`.
  2. It sends app traffic on the first **alive** channel among `HP(T)`…`HP(T+5)`, meaning one that received a
     datagram within 10 s. If none is alive, it uses the first channel that has not **failed**, and as a last
     resort `HP(T)`. A channel has failed if its probe went unanswered for 2 s or if it is older than `maxAge`.
  3. It closes a channel that has not been used for 10 s and is outside the lookahead window, so late replies
     still land. Replies from any live channel go to the last app peer. Probe ACKs only refresh the channel's
     liveness and are never forwarded to the app.
- Hot path: each reader goroutine owns a `pump`. It reads up to `batchSize` messages per recvmmsg, then sends them
  with one sendmmsg. It uses atomics only (no locks), and the hash runs once per hop. The one per-packet
  allocation is the `*net.UDPAddr` that x/net creates for each received message.
- **GRO→GSO pass-through:** every socket has `UDP_GRO` on, so the kernel can hand over many same-sized datagrams
  as one buffer plus a segment size. The pump forwards that buffer as one `UDP_SEGMENT` (GSO) send, and the
  kernel re-splits it, so datagram boundaries are preserved end to end. If a GSO send fails (no checksum offload,
  segment > MTU, old kernel), that pump logs it once and from then on splits segments itself. Probe detection
  runs only on non-coalesced datagrams.
- Socket buffers are 4 MiB (`SO_RCVBUFFORCE`/`SO_SNDBUFFORCE`, falling back to the capped `SO_RCVBUF`/`SO_SNDBUF`).
  Bursts are dropped when the receive queue is full.

## Design decisions (do not "fix")
- **No real encryption or authentication.** This is a connection-stability tool, not a protection measure. The
  fixed-IV obfuscation is deliberate: it costs no bytes per packet, and DPI resistance is its only purpose. Run a
  secure protocol (WireGuard, QUIC, TLS…) inside the tunnel if needed. As a consequence,
  anyone who can reach a port can inject packets or redirect `srvLast`. That is accepted.
- **Single reply path, no reply fan-out.** Zero (or near-zero) bandwidth overhead is a goal. Replies
  sent during the second a new NAT mapping fails may be lost, which is acceptable under UDP's lossy model.
- **No discard on wrong host:port** on the server. Clock skew is tolerated, not policed.
- **Probe = 32 zero bytes, no framing.** An app datagram of exactly 32 zero bytes collides with it and is swallowed.
  This is accepted, because framing would cost bytes on every packet. The probe traffic is one 32-byte probe per
  second from the client and up to three 32-byte ACKs per probe from the server.
- **`maxAge` = 10 s cap on sending over one socket.** Reusing a channel that has proven alive is fine, but
  long-lived NAT mappings are what buggy NATs kill.
- Packet reordering at hop boundaries is expected, and the inner protocol must tolerate it.

## Performance (measured on loopback, 8 cores, 1200-byte datagrams)
| Sender | Before batching | After |
|---|---|---|
| plain sendto, ~160k pps | 140k pps delivered, 18% loss | 150k pps, 3.8% loss (the sender is the bottleneck) |
| GSO sender, unthrottled | 143k pps / 1.4 Gbit/s | 733k pps / 7.0 Gbit/s |

Remaining ceiling: each direction is one goroutine (one core). Next steps, only if needed: several readers per
socket via `SO_REUSEPORT`, and `batchSize` tuning (memory cost: `batchSize` × 64 KiB per reader).

## Operational notes
- Without CAP_NET_ADMIN (not root), socket buffers are capped by `net.core.rmem_max`/`wmem_max`, which is often
  about 208 KiB. Raise them, for example with `sysctl -w net.core.rmem_max=4194304 net.core.wmem_max=4194304`.
- Kernel: GSO needs Linux 4.18 or newer, and GRO needs 5.0 or newer. Older kernels work without them.
- Server under high load: every hop creates a new conntrack entry. Use `iptables -t raw … -j NOTRACK` for the port range.
- Carrier-grade NATs with per-subscriber port quotas see about 30–180 live mappings per client. If
  that becomes a problem, increase `hopEvery` (a constant in `main.go`).

## Dev
```
go vet ./... && go test -v ./...   # ~7 s; ports 47000-47003, 47100-47101; 192.0.2.1 = deliberately dead host
# tests: TestTunnel (dead pairs, probe leak, GSO burst → 10×100 B intact), TestClosedReadBatch (readers exit),
#        TestObfuscate (per-pair keystream, per-segment XOR), TestPumpSplit
CGO_ENABLED=0 go build -o hoptun .   # static binary, no glibc dependency
```
Always build with `CGO_ENABLED=0`. Otherwise `net` links the cgo DNS resolver against the build
host's glibc, and the binary fails on older systems with "GLIBC_2.xx not found".
Manual: `socat UDP-LISTEN:9000,fork EXEC:cat` as the target, then run the server and client with
`hop.example.json`, then `nc -u ::1 5000`. Watch the hops with `ss -uanp`.
