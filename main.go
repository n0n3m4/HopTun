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
	"crypto/md5"
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
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv6"
)

const (
	keepFor = 10 * time.Second
	bufSize = 64 << 10
)

// hopEvery is one schedule slot (config "hop_ms"). The client timings below are wall-clock times
// converted to slots by setHop, so they don't depend on hopEvery.
var (
	hopEvery  time.Duration
	lookahead int64 // probe the slot this far ahead (5 s)
	aliveFor  int64 // a datagram this recent means the channel is alive (10 s)
	failAfter int64 // probe unanswered this long means the channel failed (2 s)
	maxAge    int64 // never send on a socket (NAT mapping) older than this (10 s)
	keepSlots int64 // close a channel unused this long (keepFor)
)

func setHop(d time.Duration) {
	hopEvery = d
	lookahead, aliveFor, failAfter, maxAge, keepSlots =
		slots(5*time.Second), slots(10*time.Second), slots(2*time.Second), slots(10*time.Second), slots(keepFor)
}

// slots converts a wall-clock time to whole slots, at least 1.
func slots(d time.Duration) int64 { return max(1, int64(d/hopEvery)) }

// slot is the schedule's clock: hopEvery periods since the Unix epoch (UTC).
func slot(t time.Time) int64 { return t.UnixNano() / int64(hopEvery) }

// zero32 is both the client probe and the server ACK.
// An app datagram of exactly 32 zero bytes collides with it and is swallowed (accepted, see CLAUDE.md).
var zero32 [32]byte

func isProbe(b []byte) bool { return bytes.Equal(b, zero32[:]) }

type Config struct {
	Hosts  []string  `json:"hosts"`
	Ports  [][2]port `json:"ports"` // inclusive ranges
	Key    string    `json:"key"`
	Target string    `json:"target"` // server only: where datagrams are forwarded
	Listen string    `json:"listen"` // client only: where the local app sends
	HopMs  int       `json:"hop_ms"` // hop interval in ms, default 100
}

// port is a config port: a JSON number, or a string with an "l" suffix for UDP-Lite ("40000l").
type port struct {
	n    int
	lite bool
}

func (p *port) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) != nil {
		s = string(b) // a plain number
	}
	s, p.lite = strings.CutSuffix(s, "l")
	var err error
	if p.n, err = strconv.Atoi(s); err != nil {
		return fmt.Errorf(`port %s: want a number, or a string like "40000l" for UDP-Lite`, b)
	}
	return nil
}

// pair is one schedule slot: a server host:port, over UDP or UDP-Lite.
type pair struct {
	netip.AddrPort
	lite bool
}

// String is the config spelling ("host:port", "host:portl"). It feeds the fingerprint and the keystream.
func (p pair) String() string {
	if p.lite {
		return p.AddrPort.String() + "l"
	}
	return p.AddrPort.String()
}

type sched struct {
	pairs []pair
	key   string
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
	if c.HopMs < 0 {
		return nil, errors.New("config: hop_ms must be positive")
	}
	if c.HopMs == 0 {
		c.HopMs = 100
	}
	setHop(time.Duration(c.HopMs) * time.Millisecond)
	var ports []port
	for _, r := range c.Ports {
		if r[0].n < 1 || r[1].n > 65535 || r[0].n > r[1].n || r[0].lite != r[1].lite {
			return nil, fmt.Errorf("config: bad port range %v (both ends need the same \"l\" suffix)", r)
		}
		for n := r[0].n; n <= r[1].n; n++ {
			ports = append(ports, port{n, r[0].lite})
		}
	}
	s := &sched{key: c.Key}
	for _, h := range c.Hosts {
		a, err := netip.ParseAddr(h)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		for _, p := range ports {
			s.pairs = append(s.pairs, pair{netip.AddrPortFrom(a.Unmap(), uint16(p.n)), p.lite})
		}
	}
	return s, nil
}

// hp is the shared schedule: HP(t) for slot t. MD5 for its avalanche: consecutive t land on
// unrelated pairs. A linear hash (FNV's last byte, CRC) walks the pair list nearly in order, which puts runs of
// one host's ports into a single lookahead window.
func (s *sched) hp(t int64) pair {
	b := binary.BigEndian.AppendUint64([]byte(s.key), uint64(t))
	h := md5.Sum(b)
	return s.pairs[binary.BigEndian.Uint64(h[:8])%uint64(len(s.pairs))]
}

// keystream obfuscates every datagram on pair ap, probes and ACKs included: AES-128-CTR keyed by
// SHA-256(key ‖ p) with a fixed zero IV, so there are no per-packet bytes. Obfuscation against DPI, not security:
// the keystream repeats for every packet on the pair (see CLAUDE.md).
// It is ksLen long and repeats for longer datagrams, so it covers every MTU-sized datagram once and costs 2 KiB
// per socket, even for a server with thousands of listeners.
func keystream(key string, p pair) []byte {
	k := sha256.Sum256([]byte(key + "\x00" + p.String()))
	b, _ := aes.NewCipher(k[:16]) // cannot fail for a 16-byte key
	ks := make([]byte, ksLen)
	cipher.NewCTR(b, make([]byte, aes.BlockSize)).XORKeyStream(ks, ks)
	return ks
}

// fingerprint lets operators compare the two sides' startup log lines.
func (s *sched) fingerprint() string {
	h := md5.New()
	h.Write([]byte(s.key))
	fmt.Fprintf(h, "\x00%d", hopEvery.Milliseconds())
	for _, p := range s.pairs {
		fmt.Fprintf(h, "\x00%s", p)
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:4])
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
	lt bool         // the listener is UDP-Lite: no GSO
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
				p.add(i, dst.ua, !dst.lt)
			}
			if err := p.flush(dst.pc); err != nil {
				logErr("reply", err)
			}
		}
	}()

	open := map[pair]*net.UDPConn{}
	for {
		now := time.Now()
		m := slot(now.Truncate(time.Minute))
		want := map[pair]bool{}
		for t := m - slots(time.Minute); t < m+slots(2*time.Minute); t++ { // current minute ±1 for clock skew
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
			conn, err := udpSock(ap, true)
			if err != nil {
				logErr("listen "+ap.String(), err)
				continue
			}
			open[ap] = conn
			go serveListener(conn, tune(conn), upPC, keystream(c.Key, ap), ap.lite)
		}
		time.Sleep(time.Until(now.Truncate(time.Minute).Add(time.Minute)))
	}
}

func serveListener(c *net.UDPConn, pc, up *ipv6.PacketConn, ks []byte, lite bool) {
	rc, err := c.SyscallConn()
	if err != nil {
		return
	}
	for {
		if err := recv(rc, pc, func(p *pump, n int) { serveBatch(p, n, c, pc, up, ks, lite) }); errors.Is(err, net.ErrClosed) {
			return
		}
	}
}

func serveBatch(p *pump, n int, c *net.UDPConn, pc, up *ipv6.PacketConn, ks []byte, lite bool) {
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
		p.add(i, nil, true)
	}
	if from == nil {
		return
	}
	if ap := from.AddrPort(); func() bool { l := srvLast.Load(); return l == nil || l.c != c || l.a != ap }() {
		srvLast.Store(&path{c, pc, ap, from, ks, lite})
	}
	if err := p.flush(up); err != nil {
		logErr("forward", err)
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
				p.add(i, nil, !h.p.lite)
			}
			if err := p.flush(h.pc); err != nil {
				logErr("send", err)
			}
		}
	}()

	// Per-pair channels, owned by this goroutine; readers touch only lastRecv.
	chans := map[pair]*chanState{}

	// open replaces p's channel with a fresh socket (fresh NAT mapping) and probes it.
	open := func(p pair, T int64) {
		h, err := udpSock(p, false)
		if err != nil {
			logErr("dial "+p.String(), err)
			return
		}
		if old := chans[p]; old != nil {
			time.AfterFunc(keepFor, func() { old.conn.Close() }) // let in-flight replies land
		}
		st := &chanState{p: p, conn: h, pc: tune(h), ks: keystream(c.Key, p), createdAt: T, probedAt: T, lastUse: T}
		chans[p] = st
		go func() { // replies on any live channel -> app
			rc, err := h.SyscallConn()
			if err != nil {
				return
			}
			for {
				if err := recv(rc, st.pc, func(p *pump, n int) { deliver(p, n, st, appPeer.Load(), appPC) }); errors.Is(err, net.ErrClosed) {
					return
				}
			}
		}()
		if _, err := h.Write(st.ks[:len(zero32)]); err != nil { // obfuscated zero32
			logErr("probe "+p.String(), err)
		}
	}

	for first := true; ; first = false {
		now := time.Now()
		T := slot(now)

		// the lookahead window HP(T)…HP(T+lookahead), hashed once per slot
		win := make([]pair, lookahead+1)
		inWin := make(map[pair]bool, len(win))
		for k := range win {
			win[k] = s.hp(T + int64(k))
			inWin[win[k]] = true
		}

		// 1. probe the lookahead slot (on startup, every slot up to it)
		k0 := int64(lookahead)
		if first {
			k0 = 0
		}
		for k := k0; k <= lookahead; k++ {
			p := win[k]
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
		for _, p := range win {
			st := chans[p]
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
			pick = chans[win[0]]
		}
		if pick != nil {
			pick.lastUse = T
			cur.Store(pick)
		}

		// 3. close channels unused for keepFor and outside the lookahead window
		for p, st := range chans {
			if T-st.lastUse > keepSlots && !inWin[p] {
				st.conn.Close()
				delete(chans, p)
			}
		}

		time.Sleep(time.Until(now.Truncate(hopEvery).Add(hopEvery)))
	}
}

// deliver forwards a batch received on channel st to the app. Probe ACKs only refresh liveness.
func deliver(p *pump, n int, st *chanState, peer *net.UDPAddr, appPC *ipv6.PacketConn) {
	st.lastRecv.Store(slot(time.Now()))
	if peer == nil {
		return
	}
	for i := 0; i < n; i++ {
		p.xor(i, st.ks)
		if p.seg[i] == 0 && isProbe(p.buf(i)) {
			continue // ACK: liveness only
		}
		p.add(i, peer, true)
	}
	if err := p.flush(appPC); err != nil {
		logErr("deliver", err)
	}
}

type chanState struct {
	p                            pair
	conn                         *net.UDPConn
	pc                           *ipv6.PacketConn
	ks                           []byte       // keystream of the channel's pair
	createdAt, probedAt, lastUse int64        // slots
	lastRecv                     atomic.Int64 // slot of the last datagram (data or ACK)
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
