package main

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestTunnel(t *testing.T) {
	c := &Config{
		Hosts:  []string{"127.0.0.1", "::1", "192.0.2.1"}, // 192.0.2.1: TEST-NET, unbindable => dead pairs
		Ports:  [][2]int{{47000, 47003}},
		Key:    "test",
		Target: "127.0.0.1:47100",
		Listen: "[::1]:47101",
	}
	s, err := newSched(c)
	if err != nil {
		t.Fatal(err)
	}
	if s.hp(1700000000) != s.hp(1700000000) || len(s.pairs) != 12 {
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
	got := make(chan int, 1000) // sizes of datagrams echoed back to the app
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, err := app.Read(buf)
			if err != nil {
				return
			}
			got <- n
		}
	}()

	seen := map[string]bool{} // server-side socket+peer paths used
	const sent = 300
	for i := 0; i < sent; i++ {
		app.Write([]byte("ping"))
		time.Sleep(10 * time.Millisecond)
		if p := srvLast.Load(); p != nil {
			seen[p.c.LocalAddr().String()+"<"+p.a.String()] = true
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
	// back as 10 separate 100-byte datagrams, whether or not GRO/GSO is used along the way.
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
		if n := <-got; n != 100 {
			t.Fatalf("GSO burst: datagram of %d bytes, want 100", n)
		}
	}
}

func TestClosedReadBatch(t *testing.T) { // readers rely on this to exit instead of spinning
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	pc := tune(c)
	c.Close()
	if _, err := newPump().read(pc); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadBatch on closed socket: %v, want net.ErrClosed", err)
	}
}

func TestPumpSplit(t *testing.T) { // coalesced buffer: GSO keeps it whole, the noGSO fallback splits on segment boundaries
	p := newPump()
	p.in[0].N, p.seg[0] = 250, 100
	p.add(0, nil)
	if len(p.out) != 1 || p.out[0].OOB == nil || len(p.out[0].Buffers[0]) != 250 {
		t.Fatalf("GSO: %d msgs", len(p.out))
	}
	p.out, p.noGSO = p.out[:0], true
	p.add(0, nil)
	if len(p.out) != 3 || len(p.out[0].Buffers[0]) != 100 || len(p.out[2].Buffers[0]) != 50 || p.out[1].OOB != nil {
		t.Fatalf("split: %d msgs", len(p.out))
	}
}
