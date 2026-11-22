# HopTun

A UDP tunnel for connection stability in roaming and lossy networks. Every second, the client
hops to a new server host:port, using a fresh local source port and therefore a fresh NAT
mapping. Both sides compute the hops from UTC time and a shared config, so there is no
handshake and no session state. NATs that drop or time out long-lived flows never see one.

```
app ⇄ client [listen] ⇄ (hopping UDP) ⇄ server [hosts × ports] ⇄ [target]
```

Before switching, the client probes each upcoming host:port 5 s ahead with a 32-zero-byte datagram, which the
server acknowledges. Traffic goes only over channels that have proven alive, so dead addresses and blocked ports
are skipped. As a side effect, an app datagram of exactly 32 zero bytes is treated as a probe and dropped.

Every datagram is obfuscated with a keystream derived from `key` and the server host:port, with zero bytes of
overhead. This only hides inner-protocol headers from DPI. It does **not** encrypt securely (the keystream repeats)
or authenticate anything. Both sides must run this version. If you need security, run a secure protocol
(WireGuard, QUIC, …) inside the tunnel.

It is Linux-only. Traffic is read and written in batches (recvmmsg/sendmmsg), with UDP GRO/GSO when the kernel
supports them. If you run it as non-root, raise `net.core.rmem_max` and `net.core.wmem_max` (for example to
4194304) so the 4 MiB socket buffers take effect.

## Build
```sh
CGO_ENABLED=0 go build -o hoptun .
```

## Config
Copy the same file to both sides:
```json
{
  "hosts":  ["2001:db8::1", "203.0.113.5"],
  "ports":  [[40000, 40015]],
  "key":    "shared",
  "target": "127.0.0.1:9000",
  "listen": "[::1]:5000"
}
```
- `hosts` × `ports` (inclusive ranges) is the set of server addresses to hop over. The server
  must have these IPs configured on its interfaces.
- A port written as a string with an `l` suffix uses UDP-Lite (IP protocol 136) in place of UDP, for example
  `[[40000, 40015], ["40000l", "40015l"]]`. Both ends of a range need the same suffix. UDP-Lite traffic must be allowed
  through firewalls separately (for example `-p udplite` in iptables).
- `target` is server-only: datagrams are forwarded there.
- `listen` is client-only: the local app sends here.
- Both sides need clocks synced to within about a minute. Each logs a `schedule fingerprint` at
  startup, and the two must match.

## Run
```sh
./hoptun server -c ./hoptun.conf
./hoptun client -c ./hoptun.conf
```

## systemd service
Run this from the directory containing `hoptun` and `hoptun.conf`. It installs a service that
starts on boot and restarts forever:
```sh
CMD='./hoptun server -c ./hoptun.conf'; printf '[Unit]\nDescription=hoptun\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n\n[Service]\nWorkingDirectory=%s\nExecStart=/bin/sh -c "exec %s"\nRestart=always\nRestartSec=1\n\n[Install]\nWantedBy=multi-user.target\n' "$PWD" "$CMD" | sudo tee /etc/systemd/system/hoptun.service >/dev/null && sudo systemctl daemon-reload && sudo systemctl enable --now hoptun
```
For the client, set `CMD='./hoptun client -c ./hoptun.conf'` and change the unit name in both
places. Check it with `systemctl status hoptun` and `journalctl -u hoptun -f`.
