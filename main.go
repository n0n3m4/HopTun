// hoptun: UDP tunnel whose client hops server host:port every second
// on a schedule both sides derive from UTC time and a shared config file.
//
//	hoptun server -c hop.json
//	hoptun client -c hop.json
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
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

	"golang.org/x/net/ipv6"
)

const (
	hopEvery = time.Second
	keepFor  = 10 * time.Second
	bufSize  = 64 << 10

	// client channel probing, all in seconds
	lookahead = 5  // probe the slot this far ahead
	aliveFor  = 10 // a datagram this recent means the channel is alive
	failAfter = 2  // probe unanswered this long means the channel failed
	maxAge    = 10 // never send on a socket (NAT mapping) older than this
	keepSec   = int64(keepFor / time.Second)
)

// zero32 is both the client probe and the server ACK.
// An app datagram of exactly 32 zero bytes collides with it and is swallowed (accepted, see CLAUDE.md).
var zero32 [32]byte

func isProbe(b []byte) bool { return bytes.Equal(b, zero32[:]) }

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

// keystream obfuscates every datagram on pair ap, probes and ACKs included: AES-128-CTR keyed by
// SHA-256(key ‖ ap) with a fixed zero IV, so there are no per-packet bytes. Obfuscation against DPI, not security:
// the keystream repeats for every packet on the pair (see CLAUDE.md).
// ponytail: bufSize (64 KiB) per pair, about 11 MiB for a server with 180 listeners.
func keystream(key string, ap netip.AddrPort) []byte {
	k := sha256.Sum256([]byte(key + "\x00" + ap.String()))
	b, _ := aes.NewCipher(k[:16]) // cannot fail for a 16-byte key
	ks := make([]byte, bufSize)
	cipher.NewCTR(b, make([]byte, aes.BlockSize)).XORKeyStream(ks, ks)
	return ks
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
	c  *net.UDPConn
	pc *ipv6.PacketConn
	a  netip.AddrPort
	ua *net.UDPAddr // a, preconverted for WriteBatch
	ks []byte       // keystream of the listener's pair
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
	upPC := tune(up)
	go func() { // target -> client, via the latest path
		p := newPump()
		for {
			n, err := p.read(upPC)
			if err != nil {
				logErr("upstream read", err) // e.g. ICMP refused; keep going
				continue
			}
			dst := srvLast.Load()
			if dst == nil {
				continue
			}
			for i := 0; i < n; i++ {
				p.xor(i, dst.ks)
				p.add(i, dst.ua)
			}
			if err := p.flush(dst.pc); err != nil {
				logErr("reply", err)
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
			go serveListener(conn, tune(conn), upPC, keystream(c.Key, ap))
		}
		time.Sleep(time.Until(now.Truncate(time.Minute).Add(time.Minute)))
	}
}

func serveListener(c *net.UDPConn, pc, up *ipv6.PacketConn, ks []byte) {
	p := newPump()
	for {
		n, err := p.read(pc)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		var from *net.UDPAddr // sender of the latest data datagram in this batch
		for i := 0; i < n; i++ {
			a, _ := p.in[i].Addr.(*net.UDPAddr)
			p.xor(i, ks)
			if p.seg[i] == 0 && isProbe(p.buf(i)) {
				if a != nil {
					go ack(c, a.AddrPort(), ks[:len(zero32)])
				}
				continue
			}
			from = a
			p.add(i, nil)
		}
		if from == nil {
			continue
		}
		if ap := from.AddrPort(); func() bool { l := srvLast.Load(); return l == nil || l.c != c || l.a != ap }() {
			srvLast.Store(&path{c, pc, ap, from, ks})
		}
		if err := p.flush(up); err != nil {
			logErr("forward", err)
		}
	}
}

// ack answers a probe thrice, 1 s apart. A probe is not data, so srvLast is left untouched.
// ackWire is zero32 obfuscated for the listener's pair.
func ack(c *net.UDPConn, to netip.AddrPort, ackWire []byte) {
	for i := 0; i < 3; i++ {
		if _, err := c.WriteToUDPAddrPort(ackWire, to); err != nil {
			return
		}
		time.Sleep(time.Second)
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
	appPC := tune(app)
	var appPeer atomic.Pointer[net.UDPAddr]
	var cur atomic.Pointer[chanState]

	go func() { // app -> current channel
		p := newPump()
		for {
			n, err := p.read(appPC)
			if err != nil || n == 0 {
				continue
			}
			if a, _ := p.in[n-1].Addr.(*net.UDPAddr); a != nil {
				if q := appPeer.Load(); q == nil || q.AddrPort() != a.AddrPort() {
					appPeer.Store(a)
				}
			}
			h := cur.Load()
			if h == nil {
				continue
			}
			for i := 0; i < n; i++ {
				p.xor(i, h.ks)
				p.add(i, nil)
			}
			if err := p.flush(h.pc); err != nil {
				logErr("send", err)
			}
		}
	}()

	// Per-pair channels, owned by this goroutine; readers touch only lastRecv.
	chans := map[netip.AddrPort]*chanState{}

	// open replaces p's channel with a fresh socket (fresh NAT mapping) and probes it.
	open := func(p netip.AddrPort, T int64) {
		h, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(p))
		if err != nil {
			logErr("dial "+p.String(), err)
			return
		}
		if old := chans[p]; old != nil {
			time.AfterFunc(keepFor, func() { old.conn.Close() }) // let in-flight replies land
		}
		st := &chanState{conn: h, pc: tune(h), ks: keystream(c.Key, p), createdAt: T, probedAt: T, lastUse: T}
		chans[p] = st
		go func() { // replies on any live channel -> app
			p := newPump()
			for {
				n, err := p.read(st.pc)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					continue
				}
				st.lastRecv.Store(time.Now().Unix())
				peer := appPeer.Load()
				if peer == nil {
					continue
				}
				for i := 0; i < n; i++ {
					p.xor(i, st.ks)
					if p.seg[i] == 0 && isProbe(p.buf(i)) {
						continue // ACK: liveness only
					}
					p.add(i, peer)
				}
				if err := p.flush(appPC); err != nil {
					logErr("deliver", err)
				}
			}
		}()
		if _, err := h.Write(st.ks[:len(zero32)]); err != nil { // obfuscated zero32
			logErr("probe "+p.String(), err)
		}
	}

	for first := true; ; first = false {
		now := time.Now()
		T := now.Unix()

		// 1. probe the lookahead slot (on startup, every slot up to it)
		k0 := int64(lookahead)
		if first {
			k0 = 0
		}
		for k := k0; k <= lookahead; k++ {
			p := s.hp(T + k)
			st := chans[p]
			if st != nil && T+k-st.createdAt < maxAge &&
				(st.lastRecv.Load() >= T-lookahead || T-st.probedAt < failAfter) {
				st.lastUse = T // alive or probe pending: reuse
				continue
			}
			open(p, T)
		}

		// 2. pick the first alive channel in schedule order, else the first not failed, else HP(T)
		var pick, maybe *chanState
	scan:
		for k := int64(0); k <= lookahead; k++ {
			st := chans[s.hp(T+k)]
			switch st.status(T) {
			case alive:
				pick = st
				break scan
			case unknown:
				if maybe == nil {
					maybe = st
				}
			}
		}
		if pick == nil {
			pick = maybe
		}
		if pick == nil {
			pick = chans[s.hp(T)]
		}
		if pick != nil {
			pick.lastUse = T
			cur.Store(pick)
		}

		// 3. close channels unused for keepFor and outside the lookahead window
		for p, st := range chans {
			if T-st.lastUse <= keepSec {
				continue
			}
			inWindow := false
			for k := int64(0); k <= lookahead && !inWindow; k++ {
				inWindow = s.hp(T+k) == p
			}
			if !inWindow {
				st.conn.Close()
				delete(chans, p)
			}
		}

		time.Sleep(time.Until(now.Truncate(hopEvery).Add(hopEvery)))
	}
}

type chanState struct {
	conn                         *net.UDPConn
	pc                           *ipv6.PacketConn
	ks                           []byte       // keystream of the channel's pair
	createdAt, probedAt, lastUse int64        // unix seconds
	lastRecv                     atomic.Int64 // unix seconds of last datagram (data or ACK)
}

const (
	failed = iota
	unknown
	alive
)

func (st *chanState) status(T int64) int {
	if st == nil || T-st.createdAt >= maxAge {
		return failed
	}
	switch r := st.lastRecv.Load(); {
	case r >= T-aliveFor:
		return alive
	case T-st.probedAt >= failAfter && r < st.probedAt:
		return failed
	}
	return unknown
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
