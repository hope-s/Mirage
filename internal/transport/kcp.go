package transport

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"

	mrand "math/rand/v2"

	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/tcpraw"
)

// Packet-based carriers. Both run KCP (reliable, loss-tolerant ARQ with
// optional Reed-Solomon FEC) underneath the usual secure layer:
//
//	kcp  - KCP over UDP
//	ftcp - KCP over fake TCP: a real TCP handshake, then raw packets that
//	       bypass the kernel TCP stack (no congestion collapse on loss,
//	       looks like TCP to filters that drop UDP). Linux + root only.
const (
	KCP  = "kcp"
	FTCP = "ftcp"
)

// IsPacket reports whether kind runs over KCP.
func IsPacket(kind string) bool { return kind == KCP || kind == FTCP }

// KCPOptions tunes the KCP carrier. Both sides must agree on Crypt, FEC
// shards and MTU; Mode and windows may differ.
type KCPOptions struct {
	// Mode is a speed preset: normal, fast, fast2 (default), fast3, turbo.
	// Faster modes retransmit sooner: lower latency on lossy links at
	// the cost of more bandwidth.
	Mode string `json:"mode,omitempty"`
	// Forward error correction: every Data packets carry Parity extra
	// ones, so up to Parity losses per group are repaired without a
	// retransmit. 0/0 disables FEC.
	Data   int `json:"fec_data,omitempty"`
	Parity int `json:"fec_parity,omitempty"`
	MTU    int `json:"mtu,omitempty"`    // default 1350
	SndWnd int `json:"sndwnd,omitempty"` // packets, default 1024
	RcvWnd int `json:"rcvwnd,omitempty"` // packets, default 1024
	// Crypt obfuscates whole packets so the KCP header is not visible:
	// aes (default), aes-128, salsa20, none. Confidentiality and
	// authentication always come from the secure layer above.
	Crypt string `json:"crypt,omitempty"`
}

type kcpPreset struct{ nodelay, interval, resend, nc int }

// Same values as kcptun's modes; turbo adds a 5 ms tick for very lossy
// links where every millisecond before a retransmit counts.
var kcpPresets = map[string]kcpPreset{
	"normal": {0, 40, 2, 1},
	"fast":   {0, 30, 2, 1},
	"fast2":  {1, 20, 2, 1},
	"fast3":  {1, 10, 2, 1},
	"turbo":  {1, 5, 2, 1},
}

// KCPModes lists the valid presets, slowest first.
var KCPModes = []string{"normal", "fast", "fast2", "fast3", "turbo"}

// WithDefaults fills unset fields.
func (o KCPOptions) WithDefaults() KCPOptions {
	if o.Mode == "" {
		o.Mode = "fast2"
	}
	if o.MTU == 0 {
		o.MTU = 1350
	}
	if o.SndWnd == 0 {
		o.SndWnd = 1024
	}
	if o.RcvWnd == 0 {
		o.RcvWnd = 1024
	}
	if o.Crypt == "" {
		o.Crypt = "aes"
	}
	return o
}

// Validate checks the options.
func (o KCPOptions) Validate() error {
	o = o.WithDefaults()
	if _, ok := kcpPresets[o.Mode]; !ok {
		return fmt.Errorf("kcp mode must be one of %v", KCPModes)
	}
	if o.Data < 0 || o.Parity < 0 || o.Data > 64 || o.Parity > 32 || (o.Data == 0) != (o.Parity == 0) {
		return errors.New("kcp fec: set both fec_data (1..64) and fec_parity (1..32), or neither")
	}
	if o.MTU < 576 || o.MTU > 1500 {
		return errors.New("kcp mtu must be 576..1500")
	}
	if o.SndWnd < 32 || o.SndWnd > 32768 || o.RcvWnd < 32 || o.RcvWnd > 32768 {
		return errors.New("kcp windows must be 32..32768")
	}
	switch o.Crypt {
	case "aes", "aes-128", "salsa20", "none":
	default:
		return errors.New("kcp crypt must be aes, aes-128, salsa20 or none")
	}
	return nil
}

func kcpBlock(crypt string, key []byte) (kcp.BlockCrypt, error) {
	if len(key) == 0 {
		return nil, errors.New("transport: kcp needs a packet key")
	}
	k := sha256.Sum256(key)
	switch crypt {
	case "aes", "":
		return kcp.NewAESBlockCrypt(k[:])
	case "aes-128":
		return kcp.NewAESBlockCrypt(k[:16])
	case "salsa20":
		return kcp.NewSalsa20BlockCrypt(k[:])
	case "none":
		return nil, nil
	}
	return nil, fmt.Errorf("transport: unknown kcp crypt %q", crypt)
}

func tuneKCP(s *kcp.UDPSession, o KCPOptions) {
	p := kcpPresets[o.Mode]
	s.SetStreamMode(true)
	s.SetWriteDelay(false)
	s.SetNoDelay(p.nodelay, p.interval, p.resend, p.nc)
	s.SetWindowSize(o.SndWnd, o.RcvWnd)
	s.SetMtu(o.MTU)
	s.SetACKNoDelay(p.nodelay == 1)
	_ = s.SetReadBuffer(4 << 20)
	_ = s.SetWriteBuffer(4 << 20)
}

func dialKCP(ctx context.Context, o DialOptions, addr string) (net.Conn, error) {
	ko := o.KCP.WithDefaults()
	if err := ko.Validate(); err != nil {
		return nil, err
	}
	block, err := kcpBlock(ko.Crypt, o.Key)
	if err != nil {
		return nil, err
	}
	var s *kcp.UDPSession
	if o.Kind == FTCP {
		type res struct {
			c   *tcpraw.TCPConn
			err error
		}
		ch := make(chan res, 1)
		go func() { c, err := tcpraw.Dial("tcp", addr); ch <- res{c, err} }()
		var r res
		select {
		case r = <-ch:
		case <-ctx.Done():
			go func() {
				if r := <-ch; r.c != nil {
					r.c.Close()
				}
			}()
			return nil, ctx.Err()
		}
		if r.err != nil {
			return nil, fmt.Errorf("fake tcp (needs linux + root): %w", r.err)
		}
		ra, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			r.c.Close()
			return nil, err
		}
		s, err = kcp.NewConn4(mrand.Uint32(), ra, block, ko.Data, ko.Parity, true, udpAddrs{r.c})
		if err != nil {
			r.c.Close()
			return nil, err
		}
	} else {
		s, err = kcp.DialWithOptions(addr, block, ko.Data, ko.Parity)
		if err != nil {
			return nil, err
		}
	}
	tuneKCP(s, ko)
	return s, nil
}

// udpAddrs makes a fake-TCP socket report peers as *net.UDPAddr: kcp-go
// silently drops packets whose source is any other address type.
type udpAddrs struct{ net.PacketConn }

func (u udpAddrs) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := u.PacketConn.ReadFrom(p)
	if ta, ok := a.(*net.TCPAddr); ok {
		a = &net.UDPAddr{IP: ta.IP, Port: ta.Port, Zone: ta.Zone}
	}
	return n, a, err
}

// kcpListener adapts a KCP listener (and the fake-TCP socket under it) to
// net.Listener, tuning every accepted session.
type kcpListener struct {
	l    *kcp.Listener
	pc   net.PacketConn // closed with the listener when we own it
	opts KCPOptions
	once sync.Once
}

func listenKCP(o ListenOptions) (net.Listener, error) {
	ko := o.KCP.WithDefaults()
	if err := ko.Validate(); err != nil {
		return nil, err
	}
	block, err := kcpBlock(ko.Crypt, o.Key)
	if err != nil {
		return nil, err
	}
	kl := &kcpListener{opts: ko}
	if o.Kind == FTCP {
		pc, err := tcpraw.Listen("tcp", o.Addr)
		if err != nil {
			return nil, fmt.Errorf("fake tcp (needs linux + root): %w", err)
		}
		kl.pc = pc
		if kl.l, err = kcp.ServeConn(block, ko.Data, ko.Parity, udpAddrs{pc}); err != nil {
			pc.Close()
			return nil, err
		}
	} else {
		if kl.l, err = kcp.ListenWithOptions(o.Addr, block, ko.Data, ko.Parity); err != nil {
			return nil, err
		}
		_ = kl.l.SetReadBuffer(8 << 20)
		_ = kl.l.SetWriteBuffer(8 << 20)
	}
	return kl, nil
}

func (k *kcpListener) Accept() (net.Conn, error) {
	s, err := k.l.AcceptKCP()
	if err != nil {
		return nil, err
	}
	tuneKCP(s, k.opts)
	return s, nil
}

func (k *kcpListener) Close() error {
	k.once.Do(func() {
		_ = k.l.Close()
		if k.pc != nil {
			_ = k.pc.Close()
		}
	})
	return nil
}

func (k *kcpListener) Addr() net.Addr { return k.l.Addr() }
