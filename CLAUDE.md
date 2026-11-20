# hoptun

UDP tunnel for connection stability in roaming and lossy networks. The client hops to a new server
host:port (and a fresh local source port, hence a fresh NAT mapping) every second, so buggy NATs
that drop or time out long-lived flows never get a long-lived flow to break. No handshake, no
session state: "connectionless connections". Exactly one client and one server.

```
app ⇄ client [listen] ⇄ (hopping UDP) ⇄ server [hosts × ports] ⇄ [target]
```

## Layout
- `main.go`: everything (config, schedule, server, client). Stdlib only.
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
- `key` only perturbs the schedule. It is **not** a security measure.
- `target` is used by the server only (the forward destination); `listen` by the client only (where the local app sends).

## How it works
- **Schedule:** `HP(t) = pairs[FNV-1a(key ‖ uint64be(t)) % len(pairs)]`, `t` = UTC unix seconds. Both sides
  must be time-synced to about ±1 minute.
- **Server:** at each minute boundary it binds every pair in `{HP(t) | t ∈ [minute−60s, minute+120s)}` and
  closes the rest. Every datagram on any open socket is forwarded to `target`, with no filtering
  for a wrong host:port. Replies from `target` go out of the socket the **latest** datagram
  arrived on, to the peer it came from (`srvLast`). Host IPs must be configured on the server's
  interfaces.
- **Client:** every second it opens `DialUDP(HP(now))` and makes that socket current for app→server traffic. Each hop
  socket stays open for 10 s to receive late replies, then closes. Replies from any live hop go to the last app peer.
- Hot path: one read and one write per datagram, atomics only (no locks), and no per-packet allocation. The hash runs once per hop.

## Design decisions (do not "fix")
- **No encryption or authentication.** This is a connection-stability tool, not a protection measure. Run a
  secure protocol (WireGuard, QUIC, TLS…) inside the tunnel if needed. As a consequence,
  anyone who can reach a port can inject packets or redirect `srvLast`. That is accepted.
- **Single reply path, no reply fan-out.** Zero (or near-zero) bandwidth overhead is a goal. Replies
  sent during the second a new NAT mapping fails may be lost, which is acceptable under UDP's lossy model.
- **No discard on wrong host:port** on the server. Clock skew is tolerated, not policed.
- Packet reordering at hop boundaries is expected, and the inner protocol must tolerate it.

## TODO (performance)
- `recvmmsg`/`sendmmsg` batching (`golang.org/x/net/ipv6.PacketConn.ReadBatch/WriteBatch`). Each
  direction is currently one goroutine (one core) doing one syscall per datagram, which tops out
  around 200–500k pps.
- UDP GSO/GRO (`UDP_SEGMENT` / `UDP_GRO`) for large-packet throughput.

## Operational notes
- Server under high load: every hop creates a new conntrack entry. Use `iptables -t raw … -j NOTRACK` for the port range.
- Carrier-grade NATs with per-subscriber port quotas see about 30–180 live mappings per client. If
  that becomes a problem, increase `hopEvery` (a constant in `main.go`).

## Dev
```
go vet ./... && go test -v ./...   # test takes ~4 s, uses ports 47000-47003, 47100-47101
CGO_ENABLED=0 go build -o hoptun .   # static binary, no glibc dependency
```
Always build with `CGO_ENABLED=0`. Otherwise `net` links the cgo DNS resolver against the build
host's glibc, and the binary fails on older systems with "GLIBC_2.xx not found".
Manual: `socat UDP-LISTEN:9000,fork EXEC:cat` as the target, then run the server and client with
`hop.example.json`, then `nc -u ::1 5000`. Watch the hops with `ss -uanp`.
