// hoptun: UDP tunnel whose client hops server host:port every second
// on a schedule both sides derive from UTC time and a shared config file.
//
//	hoptun server -c hop.json
//	hoptun client -c hop.json
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"
)

const (
	hopEvery = time.Second
	keepFor  = 10 * time.Second
	bufSize  = 64 << 10
)

type Config struct {
	Hosts  []string `json:"hosts"`
	Ports  [][2]int `json:"ports"` // inclusive ranges
	Key    string   `json:"key"`
	Target string   `json:"target"` // server only: where datagrams are forwarded
	Listen string   `json:"listen"` // client only: where the local app sends
}

type sched struct {
	pairs []netip.AddrPort
	seed  uint64 // FNV-1a state after hashing the key
}

const fnvOffset, fnvPrime = 14695981039346656037, 1099511628211

func fnv(h uint64, b []byte) uint64 {
	for _, c := range b {
		h = (h ^ uint64(c)) * fnvPrime
	}
	return h
}

func load(path string) (*Config, *sched, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	s, err := newSched(&c)
	return &c, s, err
}

func newSched(c *Config) (*sched, error) {
	if len(c.Hosts) == 0 || len(c.Ports) == 0 {
		return nil, errors.New("config: hosts and ports must be non-empty")
	}
	var ports []uint16
	for _, r := range c.Ports {
		if r[0] < 1 || r[1] > 65535 || r[0] > r[1] {
			return nil, fmt.Errorf("config: bad port range %v", r)
		}
		for p := r[0]; p <= r[1]; p++ {
			ports = append(ports, uint16(p))
		}
	}
	s := &sched{seed: fnv(fnvOffset, []byte(c.Key))}
	for _, h := range c.Hosts {
		a, err := netip.ParseAddr(h)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		for _, p := range ports {
			s.pairs = append(s.pairs, netip.AddrPortFrom(a.Unmap(), p))
		}
	}
	return s, nil
}

// hp is the shared schedule: HP(t) for t in UTC unix seconds.
func (s *sched) hp(t int64) netip.AddrPort {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(t))
	return s.pairs[fnv(s.seed, b[:])%uint64(len(s.pairs))]
}

// fingerprint lets operators compare the two sides' startup log lines.
func (s *sched) fingerprint() string {
	h := s.seed
	for _, p := range s.pairs {
		h = fnv(h, []byte(p.String()))
	}
	return fmt.Sprintf("%08x", h>>32)
}

// throttled error log, at most one line per second.
var lastLog atomic.Int64

func logErr(what string, err error) {
	now := time.Now().Unix()
	if old := lastLog.Load(); old != now && lastLog.CompareAndSwap(old, now) {
		log.Printf("%s: %v", what, err)
	}
}

// ---- server ----

type path struct {
	c *net.UDPConn
	a netip.AddrPort
}

// srvLast is where replies go: the socket+peer the latest datagram came in on.
// Single reply path (no fan-out) and no auth are deliberate, see CLAUDE.md "Design decisions".
var srvLast atomic.Pointer[path]

func runServer(c *Config, s *sched) error {
	ta, err := netip.ParseAddrPort(c.Target)
	if err != nil {
		return fmt.Errorf("config target: %w", err)
	}
	up, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ta))
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, err := up.Read(buf)
			if err != nil {
				logErr("upstream read", err) // e.g. ICMP refused; keep going
				continue
			}
			if p := srvLast.Load(); p != nil {
				if _, err := p.c.WriteToUDPAddrPort(buf[:n], p.a); err != nil {
					logErr("reply", err)
				}
			}
		}
	}()

	open := map[netip.AddrPort]*net.UDPConn{}
	for {
		now := time.Now()
		m := now.Truncate(time.Minute).Unix()
		want := map[netip.AddrPort]bool{}
		for t := m - 60; t < m+120; t++ { // current minute ±1 for clock skew
			want[s.hp(t)] = true
		}
		for ap, conn := range open {
			if !want[ap] {
				conn.Close()
				delete(open, ap)
			}
		}
		for ap := range want {
			if open[ap] != nil {
				continue
			}
			conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
			if err != nil {
				logErr("listen "+ap.String(), err)
				continue
			}
			open[ap] = conn
			go serveListener(conn, up)
		}
		time.Sleep(time.Until(now.Truncate(time.Minute).Add(time.Minute)))
	}
}

// ponytail: one syscall per datagram, ~200-500k pps per direction; recvmmsg/GSO batching is in CLAUDE.md TODO.
func serveListener(c *net.UDPConn, up *net.UDPConn) {
	buf := make([]byte, bufSize)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if p := srvLast.Load(); p == nil || p.c != c || p.a != from {
			srvLast.Store(&path{c, from})
		}
		if _, err := up.Write(buf[:n]); err != nil {
			logErr("forward", err)
		}
	}
}

// ---- client ----

func runClient(c *Config, s *sched) error {
	la, err := netip.ParseAddrPort(c.Listen)
	if err != nil {
		return fmt.Errorf("config listen: %w", err)
	}
	app, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(la))
	if err != nil {
		return err
	}
	var appPeer atomic.Pointer[netip.AddrPort]
	var cur atomic.Pointer[net.UDPConn]

	go func() { // app -> current hop
		buf := make([]byte, bufSize)
		for {
			n, from, err := app.ReadFromUDPAddrPort(buf)
			if err != nil {
				continue
			}
			if p := appPeer.Load(); p == nil || *p != from {
				appPeer.Store(&from)
			}
			if h := cur.Load(); h != nil {
				if _, err := h.Write(buf[:n]); err != nil {
					logErr("send", err)
				}
			}
		}
	}()

	for {
		now := time.Now()
		dst := s.hp(now.Unix())
		h, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(dst)) // fresh source port = fresh NAT mapping
		if err != nil {
			logErr("hop "+dst.String(), err) // keep previous hop
		} else {
			cur.Store(h)
			time.AfterFunc(keepFor, func() { h.Close() })
			go func() { // replies on any live hop -> app
				buf := make([]byte, bufSize)
				for {
					n, err := h.Read(buf)
					if err != nil {
						if errors.Is(err, net.ErrClosed) {
							return
						}
						continue
					}
					if p := appPeer.Load(); p != nil {
						app.WriteToUDPAddrPort(buf[:n], *p)
					}
				}
			}()
		}
		time.Sleep(time.Until(now.Truncate(hopEvery).Add(hopEvery)))
	}
}

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "server" && os.Args[1] != "client") {
		fmt.Fprintln(os.Stderr, "usage: hoptun server|client -c config.json")
		os.Exit(2)
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	cfgPath := fs.String("c", "hop.json", "shared config file")
	fs.Parse(os.Args[2:])

	c, s, err := load(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s: %d host:port pairs, schedule fingerprint %s", mode, len(s.pairs), s.fingerprint())
	if mode == "server" {
		err = runServer(c, s)
	} else {
		err = runClient(c, s)
	}
	log.Fatal(err)
}
