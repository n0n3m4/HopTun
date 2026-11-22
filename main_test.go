package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestTunnel(t *testing.T) {
	c := &Config{
		Hosts: []string{"127.0.0.1", "::1", "192.0.2.1"}, // 192.0.2.1: TEST-NET, unbindable => dead pairs
		// 47000l: same number, other protocol. 18 pairs: with the old FNV schedule, which walked pairs nearly in
		// order, the 6 dead 192.0.2.1 pairs came up back to back and filled the whole lookahead window.
		Ports:  [][2]port{{{47000, false}, {47003, false}}, {{47000, true}, {47001, true}}},
		Key:    "test",
		Target: "127.0.0.1:47100",
		Listen: "[::1]:47101",
	}
	s, err := newSched(c)
	if err != nil {
		t.Fatal(err)
	}
	if s.hp(1700000000) != s.hp(1700000000) || len(s.pairs) != 18 {
		t.Fatal("schedule not deterministic")
	}

	// echo upstream
	echo, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(c.Target)))
	if err != nil {
		t.Fatal(err)
	}
	var leaked atomic.Int32 // probes that reached the target (must be 0)
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, a, err := echo.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if bytes.Equal(buf[:n], zero32[:]) {
				leaked.Add(1)
			}
			echo.WriteToUDPAddrPort(buf[:n], a)
		}
	}()
	go runServer(c, s)
	time.Sleep(200 * time.Millisecond)
	go runClient(c, s)
	time.Sleep(3 * time.Second) // let first probes resolve (failAfter)

	app, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(c.Listen)))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 1000) // datagrams echoed back to the app
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, err := app.Read(buf)
			if err != nil {
				return
			}
			got <- append([]byte(nil), buf[:n]...)
		}
	}()

	seen := map[string]bool{} // server-side socket+peer paths used
	const sent = 500          // 5 s: with dead pairs the pick legitimately stays put ~1/3 of hops
	for i := 0; i < sent; i++ {
		app.Write([]byte("ping"))
		time.Sleep(10 * time.Millisecond)
		if p := srvLast.Load(); p != nil {
			seen[p.c.LocalAddr().String()+map[bool]string{true: "l"}[p.lt]+"<"+p.a.String()] = true
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(got); n < sent*9/10 {
		t.Fatalf("only %d/%d echoed", n, sent)
	}
	if n := leaked.Load(); n != 0 {
		t.Fatalf("%d probes leaked to target", n)
	}
	if len(seen) < 2 {
		t.Fatalf("no hopping observed: %v", seen)
	}
	t.Logf("echoed %d/%d over %d paths: %v", len(got), sent, len(seen), seen)

	// GSO burst from the app: 10 segments of 100 bytes in one sendmsg. It has to reach the echo target and come
	// back as 10 separate, intact 100-byte datagrams, whether or not GRO/GSO is used along the way.
	for len(got) > 0 {
		<-got
	}
	burst := make([]byte, 1000)
	for i := range burst {
		burst[i] = byte(i/100 + 1)
	}
	if _, _, err := app.WriteMsgUDP(burst, gsoCmsg(make([]byte, 64), 100), nil); err != nil {
		t.Fatalf("GSO send: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(got); n != 10 {
		t.Fatalf("GSO burst: got %d datagrams back, want 10", n)
	}
	for i := 0; i < 10; i++ {
		if b := <-got; !bytes.Equal(b, burst[i*100:(i+1)*100]) {
			t.Fatalf("GSO burst: datagram %d is %d bytes %x..., want 100 bytes of %02x", i, len(b), b[:min(4, len(b))], i+1)
		}
	}
}

func TestPorts(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"hosts":["::1"],"ports":[[1,2],["3l","4l"],["5","5"]]}`), &c); err != nil {
		t.Fatal(err)
	}
	s, err := newSched(&c)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range s.pairs {
		got = append(got, p.String())
	}
	if fmt.Sprint(got) != "[[::1]:1 [::1]:2 [::1]:3l [::1]:4l [::1]:5]" {
		t.Fatalf("pairs %v", got)
	}
	for _, bad := range []string{`[["1l",2]]`, `[["x","2"]]`} {
		c := Config{Hosts: []string{"::1"}}
		if json.Unmarshal([]byte(bad), &c.Ports) == nil {
			if _, err := newSched(&c); err == nil {
				t.Fatalf("%s accepted", bad)
			}
		}
	}
}

func TestLiteSock(t *testing.T) { // a real UDP-Lite socket (IP protocol 136), round trip over IPv4 and IPv6
	for _, a := range []string{"127.0.0.1:47102", "[::1]:47102"} {
		p := pair{netip.MustParseAddrPort(a), true}
		l, err := udpSock(p, true)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		d, err := udpSock(p, false)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		rc, _ := l.SyscallConn()
		var proto int
		rc.Control(func(fd uintptr) { proto, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PROTOCOL) })
		if proto != protoLite {
			t.Fatalf("%s: protocol %d, want %d", a, proto, protoLite)
		}
		d.Write([]byte("hi"))
		buf := make([]byte, 8)
		l.SetReadDeadline(time.Now().Add(time.Second))
		if n, _, err := l.ReadFromUDPAddrPort(buf); err != nil || string(buf[:n]) != "hi" {
			t.Fatalf("%s: read %q, %v", a, buf[:n], err)
		}
	}
}

func TestClosedReadBatch(t *testing.T) { // readers rely on this to exit instead of spinning
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	pc := tune(c)
	rc, _ := c.SyscallConn()
	done := make(chan error)
	go func() { done <- recv(rc, pc, func(*pump, int) {}) }() // parked in the poller, holding no pump
	time.Sleep(50 * time.Millisecond)
	c.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("recv on closed socket: %v, want net.ErrClosed", err)
	}
	if _, err := newPump().read(pc); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadBatch on closed socket: %v, want net.ErrClosed", err)
	}
}

func TestObfuscate(t *testing.T) { // per-pair keystreams; a GRO buffer is (de)obfuscated per segment
	a, b := pair{netip.MustParseAddrPort("127.0.0.1:1"), false}, pair{netip.MustParseAddrPort("127.0.0.1:1"), true} // same host:port, UDP vs UDP-Lite
	ka, kb := keystream("k", a), keystream("k", b)
	if bytes.Equal(ka[:32], kb[:32]) || bytes.Equal(ka[:32], zero32[:]) {
		t.Fatal("keystreams must differ per pair and from zero")
	}
	p := newPump()
	p.in[0].N, p.seg[0] = 250, 100
	p.xor(0, ka)
	for off := 0; off < 250; off += 100 {
		if !bytes.Equal(p.buf(0)[off:min(off+100, 250)], ka[:min(100, 250-off)]) {
			t.Fatalf("segment at %d not obfuscated from keystream offset 0", off)
		}
	}
	p.xor(0, ka)
	if !bytes.Equal(p.buf(0), make([]byte, 250)) {
		t.Fatal("xor twice is not identity")
	}
	p.in[0].N, p.seg[0] = ksLen+100, 0 // one datagram longer than the keystream: it repeats
	p.xor(0, ka)
	if !bytes.Equal(p.buf(0)[ksLen:], ka[:100]) {
		t.Fatal("keystream does not repeat past ksLen")
	}
}

func TestPumpSplit(t *testing.T) { // coalesced buffer: GSO keeps it whole, the noGSO fallback splits on segment boundaries
	p := newPump()
	p.in[0].N, p.seg[0] = 250, 100
	p.add(0, nil, true)
	if len(p.out) != 1 || p.out[0].OOB == nil || len(p.out[0].Buffers[0]) != 250 {
		t.Fatalf("GSO: %d msgs", len(p.out))
	}
	p.out = p.out[:0]
	p.add(0, nil, false) // UDP-Lite destination: split
	if len(p.out) != 3 || p.out[0].OOB != nil {
		t.Fatalf("gso=false: %d msgs", len(p.out))
	}
	p.out, p.noGSO = p.out[:0], true
	p.add(0, nil, true)
	if len(p.out) != 3 || len(p.out[0].Buffers[0]) != 100 || len(p.out[2].Buffers[0]) != 50 || p.out[1].OOB != nil {
		t.Fatalf("split: %d msgs", len(p.out))
	}
}

func TestRecvDrain(t *testing.T) { // full batches are re-read without the peek, and the drained queue does not block
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	pc := tune(l)
	d, _ := net.DialUDP("udp", nil, l.LocalAddr().(*net.UDPAddr))
	for i := 0; i < 3*batchSize+3; i++ {
		d.Write([]byte{byte(i), 1, 2})
	}
	rc, _ := l.SyscallConn()
	got := 0
	if err := recv(rc, pc, func(p *pump, n int) { got += n }); err != nil || got != 3*batchSize+3 {
		t.Fatalf("recv: %d datagrams, %v; want %d", got, err, 3*batchSize+3)
	}
}
