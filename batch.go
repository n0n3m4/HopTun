package main

// Batched UDP I/O: recvmmsg/sendmmsg, UDP GRO on receive, UDP GSO on send, and large socket buffers.
// Linux-only, and Linux is the only target. Every feature degrades gracefully: if a sockopt
// fails, the socket runs without it, and on the first GSO send error a pump falls back to
// splitting segments.

import (
	"crypto/subtle"
	"encoding/binary"
	"log"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv6"
)

const (
	// ponytail: batchSize × 64 KiB (the GRO max) per reader goroutine is about 0.5 MiB. That is fine for
	// tens of sockets, and mostly untouched pages for the server's worst case of 180 listeners.
	// Lower it if memory matters.
	batchSize  = 8
	solUDP     = 17      // SOL_UDP (IPPROTO_UDP); missing from package syscall
	sockBuf    = 4 << 20 // a full receive queue is where bursts get dropped
	udpSegment = 103     // UDP_SEGMENT (GSO), Linux ≥ 4.18
	udpGRO     = 104     // UDP_GRO, Linux ≥ 5.0
)

// tune enlarges socket buffers and enables GRO, ignoring failures. SO_*BUFFORCE needs
// CAP_NET_ADMIN (for example, root under systemd). Without it, the buffers are capped by
// net.core.[rw]mem_max.
func tune(c *net.UDPConn) *ipv6.PacketConn {
	if rc, err := c.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			f := int(fd)
			if syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, sockBuf) != nil {
				syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockBuf)
			}
			if syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, sockBuf) != nil {
				syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockBuf)
			}
			syscall.SetsockoptInt(f, solUDP, udpGRO, 1)
		})
	}
	// The ipv6 wrapper parses sockaddrs by their family, so it serves IPv4 sockets too.
	return ipv6.NewPacketConn(c)
}

// pump reads one batch and forwards it, keeping GRO-coalesced buffers intact through GSO.
// Each pump is owned by a single goroutine.
// ponytail: x/net allocates a *net.UDPAddr for every received message. Batching amortizes the
// syscalls, but not this allocation.
type pump struct {
	in    []ipv6.Message
	seg   []int // GRO segment size per in message, 0 = a plain datagram
	gso   [][]byte
	out   []ipv6.Message
	noGSO bool
}

func newPump() *pump {
	p := &pump{in: make([]ipv6.Message, batchSize), seg: make([]int, batchSize), gso: make([][]byte, batchSize)}
	for i := range p.in {
		p.in[i].Buffers = [][]byte{make([]byte, bufSize)}
		p.in[i].OOB = make([]byte, syscall.CmsgSpace(4))
		p.gso[i] = make([]byte, syscall.CmsgSpace(2))
	}
	return p
}

func (p *pump) read(c *ipv6.PacketConn) (int, error) {
	p.out = p.out[:0]
	n, err := c.ReadBatch(p.in, 0)
	for i := 0; i < n; i++ {
		p.seg[i] = groSize(p.in[i].OOB[:p.in[i].NN])
	}
	return n, err
}

// buf is message i's payload: one datagram, or GRO-coalesced segments of seg[i] bytes (the last may be shorter).
func (p *pump) buf(i int) []byte { return p.in[i].Buffers[0][:p.in[i].N] }

// xor (de)obfuscates message i in place. Every datagram, including each GRO segment, starts at keystream offset 0.
func (p *pump) xor(i int, ks []byte) {
	b, s := p.buf(i), p.seg[i]
	if s == 0 {
		s = len(b)
	}
	for len(b) > 0 {
		n := min(s, len(b))
		subtle.XORBytes(b[:n], b[:n], ks)
		b = b[n:]
	}
}

// add queues in-message i for sending to `to`. Pass nil for a connected socket.
func (p *pump) add(i int, to net.Addr) {
	b, s := p.buf(i), p.seg[i]
	switch {
	case s == 0 || s >= len(b):
		p.push(b, nil, to)
	case !p.noGSO:
		p.push(b, gsoCmsg(p.gso[i], s), to)
	default:
		p.split(b, s, to)
	}
}

func (p *pump) split(b []byte, s int, to net.Addr) {
	for len(b) > 0 {
		n := min(s, len(b))
		p.push(b[:n], nil, to)
		b = b[n:]
	}
}

// push appends to out, reusing the Buffers slices from earlier batches (no per-packet allocation).
func (p *pump) push(b, oob []byte, to net.Addr) {
	if len(p.out) < cap(p.out) {
		p.out = p.out[:len(p.out)+1] // reuse the slot, keeping its Buffers
	} else {
		p.out = append(p.out, ipv6.Message{})
	}
	m := &p.out[len(p.out)-1]
	if m.Buffers == nil { // first use of this slot (append's spare capacity is zero-valued)
		m.Buffers = make([][]byte, 1)
	}
	m.Buffers[0], m.OOB, m.Addr = b, oob, to
}

// flush sends everything queued. If one message fails, that message is dropped and the rest are
// still sent. If a GSO message fails (no checksum offload, segment > MTU, or an old kernel),
// GSO is turned off for this pump and the remaining messages are re-sent as split segments.
func (p *pump) flush(c *ipv6.PacketConn) (err error) {
	ms := p.out
	for len(ms) > 0 {
		n, werr := c.WriteBatch(ms, 0)
		ms = ms[n:]
		if len(ms) == 0 {
			break
		}
		if werr == nil {
			if n == 0 {
				break // no progress and no error; don't spin
			}
			continue
		}
		err = werr
		if ms[0].OOB != nil {
			log.Printf("UDP GSO send failed (%v), falling back to plain sends", werr)
			p.noGSO = true
			// Copy out before re-pushing: push reuses the Buffers slices that ms points into.
			type pend struct {
				b   []byte
				seg int
				to  net.Addr
			}
			rest := make([]pend, len(ms))
			for i, m := range ms {
				rest[i] = pend{m.Buffers[0], 0, m.Addr}
				if m.OOB != nil {
					rest[i].seg = int(binary.NativeEndian.Uint16(m.OOB[syscall.CmsgLen(0):]))
				}
			}
			p.out = p.out[:0]
			for _, r := range rest {
				if r.seg > 0 {
					p.split(r.b, r.seg, r.to)
				} else {
					p.push(r.b, nil, r.to)
				}
			}
			ms = p.out
			continue
		}
		ms = ms[1:] // drop the failed datagram, e.g. ECONNREFUSED after an ICMP unreachable
	}
	return err
}

func groSize(oob []byte) int {
	if len(oob) == 0 {
		return 0
	}
	cms, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, cm := range cms {
		if cm.Header.Level == solUDP && cm.Header.Type == udpGRO && len(cm.Data) >= 4 {
			return int(binary.NativeEndian.Uint32(cm.Data))
		}
	}
	return 0
}

func gsoCmsg(b []byte, seg int) []byte {
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = solUDP, udpSegment
	h.SetLen(syscall.CmsgLen(2))
	binary.NativeEndian.PutUint16(b[syscall.CmsgLen(0):], uint16(seg))
	return b[:syscall.CmsgSpace(2)]
}
