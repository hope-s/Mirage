// Package node wires transports, the secure layer and the multiplexer into a
// running iran (entry) or kharej (exit) node.
package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"mirage/internal/mux"
	"mirage/internal/secure"
	"mirage/internal/transport"
)

const handshakeTimeout = 15 * time.Second

// Node is a running Mirage instance.
type Node struct {
	cfg    *Config
	prof   profile
	psk    secure.PSK
	log    *logger
	pool   *Pool // iran only
	exit   *exit // kharej only
	replay *secure.ReplayCache

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	closers []io.Closer

	linksMu sync.Mutex
	links   map[string]*linkState

	allMu sync.Mutex
	all   map[*mux.Session]sessInfo // every live session, both roles

	doneIn, doneOut atomic.Uint64 // bytes of sessions that already closed
}

type linkState struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"` // dial | listen
	Transport string `json:"transport"`
	Want      int    `json:"want,omitempty"`
	Min       int    `json:"min,omitempty"`
	Backup    bool   `json:"backup,omitempty"`
	Disabled  bool   `json:"disabled,omitempty"`
	Up        int32  `json:"up"`
	LastError string `json:"last_error,omitempty"`
	up        atomic.Int32
	mu        sync.Mutex
}

// New prepares a node from a validated config.
func New(cfg *Config) (*Node, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	psk, err := cfg.PSK()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		cfg: cfg, psk: psk, log: &logger{debug: cfg.Debug}, prof: profileFor(cfg.Profile),
		replay: secure.NewReplayCache(),
		ctx:    ctx, cancel: cancel,
		links: map[string]*linkState{},
		all:   map[*mux.Session]sessInfo{},
	}
	if cfg.Role == RoleIran {
		n.pool = newPool()
	} else {
		pol, err := ParseAllowLocal(cfg.AllowLocal)
		if err != nil {
			cancel()
			return nil, err
		}
		n.exit = &exit{policy: pol, log: n.log}
	}
	return n, nil
}

// Start binds every listener and starts every dialer. On error nothing is
// left running.
func (n *Node) Start() (err error) {
	defer func() {
		if err != nil {
			n.Close()
		}
	}()
	for _, l := range n.cfg.Listen {
		tl, err := transport.Listen(transport.ListenOptions{
			Kind: l.Transport, Addr: l.Addr, CertFile: l.Cert, KeyFile: l.CertKey,
			SNI: l.SNI, Path: l.Path, Fallback: l.Fallback,
		})
		if err != nil {
			return fmt.Errorf("listen %s (%s %s): %w", l.Name, l.Transport, l.Addr, err)
		}
		n.closers = append(n.closers, tl)
		st := n.link(l.Name, "listen", l.Transport, 0)
		st.Backup = l.Backup
		n.wg.Add(1)
		go n.acceptLoop(tl, l, st)
		n.log.infof("listening %s on %s (%s)", l.Name, tl.Addr(), l.Transport)
	}
	for _, f := range n.cfg.Forward {
		if f.Proto == "tcp" || f.Proto == "both" {
			ln, err := net.Listen("tcp", f.Listen)
			if err != nil {
				return fmt.Errorf("forward tcp %s: %w", f.Listen, err)
			}
			n.closers = append(n.closers, ln)
			go n.serveTCPForward(ln, f.Target)
			n.log.infof("forward tcp %s -> %s", f.Listen, f.Target)
		}
		if f.Proto == "udp" || f.Proto == "both" {
			ua, err := net.ResolveUDPAddr("udp", f.Listen)
			if err != nil {
				return fmt.Errorf("forward udp %s: %w", f.Listen, err)
			}
			pc, err := net.ListenUDP("udp", ua)
			if err != nil {
				return fmt.Errorf("forward udp %s: %w", f.Listen, err)
			}
			n.closers = append(n.closers, pc)
			go n.serveUDPForward(pc, f.Target)
			n.log.infof("forward udp %s -> %s", f.Listen, f.Target)
		}
	}
	for _, s := range n.cfg.Socks {
		ln, err := net.Listen("tcp", s.Listen)
		if err != nil {
			return fmt.Errorf("socks %s: %w", s.Listen, err)
		}
		n.closers = append(n.closers, ln)
		go n.serveSocks(ln, s)
		n.log.infof("socks5 on %s", s.Listen)
		if h, _, _ := net.SplitHostPort(s.Listen); s.User == "" {
			if ip := net.ParseIP(h); h != "localhost" && (ip == nil || !ip.IsLoopback()) {
				n.log.infof("WARNING: socks5 %s is reachable from the network without a password; set user/pass or listen on 127.0.0.1", s.Listen)
			}
		}
	}
	for _, d := range n.cfg.Dial {
		if d.Disabled {
			st := n.link(d.Name, "dial", d.Transport, 0)
			st.Disabled, st.Backup, st.Min = true, d.Backup, max(d.Conns, 1)
			n.log.infof("link %s is disabled", d.Name)
			continue
		}
		n.startDialLink(d)
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-n.ctx.Done():
				return
			case <-t.C:
				n.replay.Sweep()
			}
		}
	}()
	return nil
}

// Close stops everything.
func (n *Node) Close() {
	n.cancel()
	for _, c := range n.closers {
		_ = c.Close()
	}
	n.allMu.Lock()
	for s := range n.all {
		_ = s.Close()
	}
	n.allMu.Unlock()
	n.wg.Wait()
}

// Pool exposes the session pool (tests).
func (n *Node) Pool() *Pool { return n.pool }

func (n *Node) link(name, kind, tr string, want int) *linkState {
	n.linksMu.Lock()
	defer n.linksMu.Unlock()
	st := &linkState{Name: name, Kind: kind, Transport: tr, Want: want}
	n.links[name] = st
	return st
}

func (st *linkState) setErr(err error) {
	st.mu.Lock()
	if err == nil {
		st.LastError = ""
	} else {
		st.LastError = err.Error()
	}
	st.mu.Unlock()
}

// register attaches a fresh session to this node's role.
func (n *Node) register(s *mux.Session, info sessInfo, st *linkState) {
	n.allMu.Lock()
	n.all[s] = info
	n.allMu.Unlock()
	st.up.Add(1)
	go func() {
		<-s.Done()
		st.up.Add(-1)
		n.allMu.Lock()
		delete(n.all, s)
		n.doneIn.Add(s.BytesIn.Load())
		n.doneOut.Add(s.BytesOut.Load())
		n.allMu.Unlock()
		n.log.debugf("session %s %s closed: %v", info.Link, info.Remote, s.Err())
	}()
	if n.pool != nil {
		n.pool.add(s, info)
		// the exit side never opens streams; refuse any that appear
		go func() {
			for {
				x, err := s.Accept()
				if err != nil {
					return
				}
				x.Reset()
			}
		}()
	} else {
		go n.exit.serve(s)
	}
}

func (n *Node) acceptLoop(tl *transport.Listener, l ListenConf, st *linkState) {
	defer n.wg.Done()
	for {
		c, err := tl.Accept()
		if err != nil {
			return
		}
		go func() {
			sc, br, err := secure.Server(c, n.psk, n.replay, handshakeTimeout)
			if err != nil {
				n.log.debugf("listen %s: rejected %s: %v", l.Name, c.RemoteAddr(), err)
				if errors.Is(err, secure.ErrHTTP) {
					tl.Reject(c, br, true)
				} else if errors.Is(err, secure.ErrAuth) {
					tl.Reject(c, br, false)
				} else {
					c.Close()
				}
				return
			}
			sc.SetPadding(n.prof.pad)
			s := mux.New(sc, false, n.prof.mux)
			n.log.debugf("listen %s: session from %s", l.Name, c.RemoteAddr())
			n.register(s, sessInfo{Link: l.Name, Transport: l.Transport, Remote: c.RemoteAddr().String(), Backup: l.Backup}, st)
			if n.ctx.Err() != nil {
				s.Close()
			}
		}()
	}
}

func (n *Node) lifetime() time.Duration {
	lo, hi := n.cfg.RotateMin, n.cfg.RotateMax
	if lo <= 0 {
		return 0
	}
	d := lo
	if hi > lo {
		d += mrand.IntN(hi - lo + 1)
	}
	return time.Duration(d) * time.Second
}

func (n *Node) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-n.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (n *Node) dialOnce(o transport.DialOptions) (*mux.Session, string, error) {
	ctx, cancel := context.WithTimeout(n.ctx, 20*time.Second)
	defer cancel()
	c, err := transport.Dial(ctx, o)
	if err != nil {
		return nil, "", err
	}
	sc, err := secure.Client(c, n.psk, handshakeTimeout)
	if err != nil {
		c.Close()
		if errors.Is(err, io.EOF) || errors.Is(err, secure.ErrAuth) {
			return nil, "", fmt.Errorf("handshake rejected: wrong token/key, the port is not mirage, or the two servers' clocks differ by over 2 minutes (check timedatectl): %w", err)
		}
		return nil, "", fmt.Errorf("handshake: %w", err)
	}
	sc.SetPadding(n.prof.pad)
	return mux.New(sc, true, n.prof.mux), c.RemoteAddr().String(), nil
}

// drainAndClose closes a rotated session once its streams finish (or after
// a hard limit so it cannot linger forever).
func drainAndClose(ctx context.Context, s *mux.Session) {
	limit := time.After(30 * time.Minute)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.Close()
			return
		case <-s.Done():
			return
		case <-limit:
			s.Close()
			return
		case <-t.C:
			if s.NumStreams() == 0 {
				s.Close()
				return
			}
		}
	}
}

// ---------- status ----------

// SessionStatus is one row in the status output.
type SessionStatus struct {
	Link      string  `json:"link"`
	Transport string  `json:"transport"`
	Remote    string  `json:"remote"`
	Dialed    bool    `json:"dialed"`
	Backup    bool    `json:"backup"`
	RTTms     float64 `json:"rtt_ms"`
	Streams   int     `json:"streams"`
	AgeSec    int     `json:"age_s"`
	Draining  bool    `json:"draining"`
	BytesIn   uint64  `json:"bytes_in"`
	BytesOut  uint64  `json:"bytes_out"`
}

// Status is the JSON served on the status address.
type Status struct {
	Role     string          `json:"role"`
	Links    []*linkState    `json:"links"`
	Sessions []SessionStatus `json:"sessions"`
}

// Snapshot returns the current status.
func (n *Node) Snapshot() Status {
	out := Status{Role: n.cfg.Role}
	n.linksMu.Lock()
	for _, l := range n.links {
		l.mu.Lock()
		cp := &linkState{Name: l.Name, Kind: l.Kind, Transport: l.Transport, Want: l.Want, LastError: l.LastError,
			Min: l.Min, Backup: l.Backup, Disabled: l.Disabled}
		l.mu.Unlock()
		cp.Up = l.up.Load()
		out.Links = append(out.Links, cp)
	}
	n.linksMu.Unlock()
	sort.Slice(out.Links, func(i, j int) bool { return out.Links[i].Name < out.Links[j].Name })
	n.allMu.Lock()
	for s, info := range n.all {
		out.Sessions = append(out.Sessions, SessionStatus{
			Link: info.Link, Transport: info.Transport, Remote: info.Remote, Dialed: info.Dialed, Backup: info.Backup,
			RTTms: float64(s.RTT().Microseconds()) / 1000, Streams: s.NumStreams(),
			AgeSec: int(time.Since(s.CreatedAt).Seconds()), Draining: s.Draining(),
			BytesIn: s.BytesIn.Load(), BytesOut: s.BytesOut.Load(),
		})
	}
	n.allMu.Unlock()
	sort.Slice(out.Sessions, func(i, j int) bool {
		if out.Sessions[i].Link != out.Sessions[j].Link {
			return out.Sessions[i].Link < out.Sessions[j].Link
		}
		return out.Sessions[i].AgeSec > out.Sessions[j].AgeSec
	})
	return out
}

// Config returns the node's configuration (read-only).
func (n *Node) Config() *Config { return n.cfg }

// Totals returns cumulative bytes over all live sessions.
func (n *Node) Totals() (in, out uint64) {
	n.allMu.Lock()
	defer n.allMu.Unlock()
	in, out = n.doneIn.Load(), n.doneOut.Load()
	for s := range n.all {
		in += s.BytesIn.Load()
		out += s.BytesOut.Load()
	}
	return
}
