package main

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestTunnel(t *testing.T) {
	c := &Config{
		Hosts:  []string{"127.0.0.1", "::1"},
		Ports:  [][2]int{{47000, 47003}},
		Key:    "test",
		Target: "127.0.0.1:47100",
		Listen: "[::1]:47101",
	}
	s, err := newSched(c)
	if err != nil {
		t.Fatal(err)
	}
	if s.hp(1700000000) != s.hp(1700000000) || len(s.pairs) != 8 {
		t.Fatal("schedule not deterministic")
	}

	// echo upstream
	echo, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(c.Target)))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, a, err := echo.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			echo.WriteToUDPAddrPort(buf[:n], a)
		}
	}()
	go runServer(c, s)
	time.Sleep(200 * time.Millisecond)
	go runClient(c, s)
	time.Sleep(200 * time.Millisecond)

	app, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(c.Listen)))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{}, 1000)
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := app.Read(buf); err != nil {
				return
			}
			got <- struct{}{}
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
	if len(seen) < 2 {
		t.Fatalf("no hopping observed: %v", seen)
	}
	t.Logf("echoed %d/%d over %d paths: %v", len(got), sent, len(seen), seen)
}
