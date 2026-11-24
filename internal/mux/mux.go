// Package mux multiplexes many logical streams over one reliable connection
// with per-stream credit-based flow control, so one slow stream can never
// stall the others (no head-of-line blocking inside the session).
package mux

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cmdSYN    = 1
	cmdSYNACK = 2
	cmdDATA   = 3
	cmdFIN    = 4
	cmdRST    = 5
	cmdWND    = 6
	cmdPING   = 7
	cmdPONG   = 8
	cmdGOAWAY = 9

	hdrLen  = 7
	maxData = 16 * 1024

	// InitialWindow is the receive window every stream starts with. It
	// grows automatically (doubling, like QUIC) while the reader keeps up,
	// up to Config.MaxWindow, so fast links reach full speed and idle or
	// slow streams use little memory.
	InitialWindow = 256 << 10
	// Window is the default MaxWindow.
	Window = 8 << 20

	acceptBacklog = 1024
)

var (
	ErrClosed  = errors.New("mux: session closed")
	ErrReset   = errors.New("mux: stream reset")
	ErrRefused = errors.New("mux: connection refused by remote")
	ErrGoAway  = errors.New("mux: session is draining")
	ErrTimeout = errors.New("mux: timeout")
)

// Config tunes keepalive behaviour.
type Config struct {
	PingInterval time.Duration // default 5s
	IdleTimeout  time.Duration // close if nothing received for this long; default 20s
	MaxWindow    int           // per-stream receive window ceiling; default Window
}

// Session is one multiplexed connection.
type Session struct {
	conn io.ReadWriteCloser
	br   *bufio.Reader
	cfg  Config

	wmu  sync.Mutex
	wbuf []byte

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32

	acceptCh  chan *Stream
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	localGoAway  atomic.Bool
	remoteGoAway atomic.Bool

	lastRecv  atomic.Int64
	rtt       atomic.Int64 // ns, EWMA; 0 = unknown
	pingMu    sync.Mutex
	pingSent  map[uint64]time.Time
	BytesIn   atomic.Uint64
	BytesOut  atomic.Uint64
	CreatedAt time.Time
}

// New creates a session. client decides stream-ID parity.
func New(conn io.ReadWriteCloser, client bool, cfg Config) *Session {
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = 5 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 20 * time.Second
	}
	if cfg.MaxWindow < InitialWindow {
		cfg.MaxWindow = Window
	}
	s := &Session{
		conn:      conn,
		br:        bufio.NewReaderSize(conn, 64*1024),
		cfg:       cfg,
		streams:   make(map[uint32]*Stream),
		acceptCh:  make(chan *Stream, acceptBacklog),
		closed:    make(chan struct{}),
		pingSent:  make(map[uint64]time.Time),
		CreatedAt: time.Now(),
	}
	if client {
		s.nextID = 1
	} else {
		s.nextID = 2
	}
	s.lastRecv.Store(time.Now().UnixNano())
	go s.readLoop()
	go s.keepalive()
	return s
}

// Close tears down the session and all streams.
func (s *Session) Close() error { s.closeWith(ErrClosed); return nil }

func (s *Session) closeWith(err error) {
	s.closeOnce.Do(func() {
		s.closeErr = err
		close(s.closed)
		_ = s.conn.Close()
		s.mu.Lock()
		streams := s.streams
		s.streams = make(map[uint32]*Stream)
		s.mu.Unlock()
		for _, st := range streams {
			st.fail(ErrClosed)
		}
	})
}

// Done is closed when the session dies.
func (s *Session) Done() <-chan struct{} { return s.closed }

// IsClosed reports whether the session is dead.
func (s *Session) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// Err returns why the session closed.
func (s *Session) Err() error {
	select {
	case <-s.closed:
		return s.closeErr
	default:
		return nil
	}
}

// NumStreams returns the number of open streams.
func (s *Session) NumStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

// RTT returns the smoothed round-trip time, or 0 if unknown.
func (s *Session) RTT() time.Duration { return time.Duration(s.rtt.Load()) }

// GoAway tells the peer to stop opening new streams; existing ones finish.
func (s *Session) GoAway() {
	if s.localGoAway.CompareAndSwap(false, true) {
		_ = s.writeFrame(cmdGOAWAY, 0, nil)
	}
}

// Draining reports whether either side asked to stop opening streams.
func (s *Session) Draining() bool { return s.localGoAway.Load() || s.remoteGoAway.Load() }

func (s *Session) writeFrame(cmd byte, sid uint32, payload []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.IsClosed() {
		return ErrClosed
	}
	need := hdrLen + len(payload)
	if cap(s.wbuf) < need {
		s.wbuf = make([]byte, need, hdrLen+maxData)
	}
	buf := s.wbuf[:need]
	buf[0] = cmd
	binary.BigEndian.PutUint32(buf[1:5], sid)
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(payload)))
	copy(buf[hdrLen:], payload)
	if _, err := s.conn.Write(buf); err != nil {
		s.closeWith(err)
		return ErrClosed
	}
	s.BytesOut.Add(uint64(len(buf)))
	return nil
}

func (s *Session) keepalive() {
	// Jittered interval so keepalives don't form a perfectly periodic,
	// fingerprintable pattern.
	t := time.NewTimer(s.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
		}
		j := int64(s.cfg.PingInterval) * 6 / 10
		var rb [8]byte
		_, _ = rand.Read(rb[:])
		t.Reset(time.Duration(int64(s.cfg.PingInterval)*7/10 + int64(binary.BigEndian.Uint64(rb[:])%uint64(j))))
		if time.Since(time.Unix(0, s.lastRecv.Load())) > s.cfg.IdleTimeout {
			s.closeWith(ErrTimeout)
			return
		}
		var b [8]byte
		_, _ = rand.Read(b[:])
		id := binary.BigEndian.Uint64(b[:])
		s.pingMu.Lock()
		now := time.Now()
		for k, v := range s.pingSent {
			if now.Sub(v) > s.cfg.IdleTimeout {
				delete(s.pingSent, k)
			}
		}
		s.pingSent[id] = now
		s.pingMu.Unlock()
		_ = s.writeFrame(cmdPING, 0, b[:])
	}
}

func (s *Session) readLoop() {
	var hdr [hdrLen]byte
	for {
		if _, err := io.ReadFull(s.br, hdr[:]); err != nil {
			s.closeWith(err)
			return
		}
		cmd := hdr[0]
		sid := binary.BigEndian.Uint32(hdr[1:5])
		n := int(binary.BigEndian.Uint16(hdr[5:7]))
		payload := make([]byte, n)
		if _, err := io.ReadFull(s.br, payload); err != nil {
			s.closeWith(err)
			return
		}
		s.lastRecv.Store(time.Now().UnixNano())
		s.BytesIn.Add(uint64(hdrLen + n))
		if err := s.handle(cmd, sid, payload); err != nil {
			s.closeWith(err)
			return
		}
	}
}

var errProto = errors.New("mux: protocol violation")

func (s *Session) handle(cmd byte, sid uint32, p []byte) error {
	switch cmd {
	case cmdSYN:
		// Streams that race with our GOAWAY are still accepted; the
		// session only closes once it has no streams left.
		st := newStream(s, sid, string(p))
		st.connected = true
		close(st.connCh)
		s.mu.Lock()
		if _, dup := s.streams[sid]; dup {
			s.mu.Unlock()
			return errProto
		}
		s.streams[sid] = st
		s.mu.Unlock()
		select {
		case s.acceptCh <- st:
		default:
			s.remove(sid)
			_ = s.writeFrame(cmdRST, sid, nil)
		}
	case cmdSYNACK:
		if st := s.get(sid); st != nil {
			st.setConnected(len(p) > 0 && p[0] == 0)
		}
	case cmdDATA:
		st := s.get(sid)
		if st == nil {
			return nil // stream already gone; data is dropped
		}
		if !st.push(p) {
			return errProto // peer overran our window
		}
	case cmdFIN:
		if st := s.get(sid); st != nil {
			st.remoteFin()
		}
	case cmdRST:
		if st := s.get(sid); st != nil {
			s.remove(sid)
			st.fail(ErrReset)
		}
	case cmdWND:
		if len(p) != 4 {
			return errProto
		}
		if st := s.get(sid); st != nil {
			st.addCredit(int64(binary.BigEndian.Uint32(p)))
		}
	case cmdPING:
		_ = s.writeFrame(cmdPONG, 0, p)
	case cmdPONG:
		if len(p) == 8 {
			id := binary.BigEndian.Uint64(p)
			s.pingMu.Lock()
			t, ok := s.pingSent[id]
			delete(s.pingSent, id)
			s.pingMu.Unlock()
			if ok {
				sample := int64(time.Since(t))
				old := s.rtt.Load()
				if old == 0 {
					s.rtt.Store(sample)
				} else {
					s.rtt.Store(old - old/4 + sample/4)
				}
			}
		}
	case cmdGOAWAY:
		s.remoteGoAway.Store(true)
	default:
		return errProto
	}
	return nil
}

func (s *Session) get(sid uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[sid]
}

func (s *Session) remove(sid uint32) {
	s.mu.Lock()
	delete(s.streams, sid)
	s.mu.Unlock()
}

// Open opens a stream whose SYN carries target. It does not wait for the
// peer; call Stream.WaitConnected for that.
func (s *Session) Open(target string) (*Stream, error) {
	if len(target) > 1024 {
		return nil, errors.New("mux: target too long")
	}
	if s.Draining() {
		return nil, ErrGoAway
	}
	s.mu.Lock()
	if s.IsClosed() {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	sid := s.nextID
	s.nextID += 2
	st := newStream(s, sid, target)
	s.streams[sid] = st
	s.mu.Unlock()
	if err := s.writeFrame(cmdSYN, sid, []byte(target)); err != nil {
		s.remove(sid)
		return nil, err
	}
	return st, nil
}

// Accept waits for a stream opened by the peer.
func (s *Session) Accept() (*Stream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-s.closed:
		return nil, ErrClosed
	}
}

// Stream is one logical bidirectional byte stream.
type Stream struct {
	sess   *Session
	id     uint32
	Target string

	mu        sync.Mutex
	rq        [][]byte
	rqBytes   int
	finRecv   bool
	finSent   bool
	err       error
	unacked   int // bytes consumed by reader not yet credited back
	recvWin   int // current receive window (auto-tuned)
	lastCred  time.Time
	sendCred  int64
	readable  chan struct{}
	writable  chan struct{}
	connCh    chan struct{}
	connected bool
	refused   bool
	closed    bool
}

func newStream(s *Session, id uint32, target string) *Stream {
	return &Stream{
		sess:     s,
		id:       id,
		Target:   target,
		sendCred: InitialWindow,
		recvWin:  InitialWindow,
		lastCred: time.Now(),
		readable: make(chan struct{}, 1),
		writable: make(chan struct{}, 1),
		connCh:   make(chan struct{}),
	}
}

func notify(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func (st *Stream) setConnected(ok bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	select {
	case <-st.connCh:
		return
	default:
	}
	st.connected = ok
	st.refused = !ok
	close(st.connCh)
}

// Accept (server side) acknowledges the stream; ok=false refuses it.
func (st *Stream) Accept(ok bool) error {
	code := byte(0)
	if !ok {
		code = 1
	}
	err := st.sess.writeFrame(cmdSYNACK, st.id, []byte{code})
	if !ok {
		st.sess.remove(st.id)
		st.fail(ErrRefused)
	}
	return err
}

// WaitConnected blocks until the peer acknowledged the stream.
func (st *Stream) WaitConnected(timeout time.Duration) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-st.connCh:
		st.mu.Lock()
		defer st.mu.Unlock()
		if st.refused {
			return ErrRefused
		}
		if st.err != nil {
			return st.err
		}
		return nil
	case <-st.sess.closed:
		return ErrClosed
	case <-t.C:
		st.Reset()
		return ErrTimeout
	}
}

func (st *Stream) push(p []byte) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.err != nil || st.closed {
		return true // discard silently
	}
	if st.rqBytes+len(p) > st.recvWin {
		return false
	}
	if len(p) > 0 {
		st.rq = append(st.rq, p)
		st.rqBytes += len(p)
	}
	notify(st.readable)
	return true
}

func (st *Stream) remoteFin() {
	st.mu.Lock()
	st.finRecv = true
	done := st.finSent
	st.mu.Unlock()
	notify(st.readable)
	if done {
		st.sess.remove(st.id)
	}
}

func (st *Stream) addCredit(n int64) {
	st.mu.Lock()
	st.sendCred += n
	st.mu.Unlock()
	notify(st.writable)
}

func (st *Stream) fail(err error) {
	st.mu.Lock()
	if st.err == nil {
		st.err = err
	}
	select {
	case <-st.connCh:
	default:
		close(st.connCh)
	}
	st.mu.Unlock()
	notify(st.readable)
	notify(st.writable)
}

// Read implements io.Reader.
func (st *Stream) Read(p []byte) (int, error) {
	for {
		st.mu.Lock()
		if len(st.rq) > 0 {
			n := 0
			for n < len(p) && len(st.rq) > 0 {
				c := copy(p[n:], st.rq[0])
				n += c
				if c == len(st.rq[0]) {
					st.rq = st.rq[1:]
				} else {
					st.rq[0] = st.rq[0][c:]
				}
			}
			st.rqBytes -= n
			st.unacked += n
			var credit int
			if st.unacked >= st.recvWin/4 || (len(st.rq) == 0 && st.unacked >= 32*1024) {
				credit = st.unacked
				st.unacked = 0
				// Auto-tune: if the window is being consumed in less
				// than ~2 RTTs, the window (not the network) limits
				// throughput, so double it.
				now := time.Now()
				rtt := st.sess.RTT()
				if rtt <= 0 {
					rtt = 100 * time.Millisecond
				}
				if st.recvWin < st.sess.cfg.MaxWindow && now.Sub(st.lastCred) < 2*rtt {
					grow := st.recvWin
					if st.recvWin+grow > st.sess.cfg.MaxWindow {
						grow = st.sess.cfg.MaxWindow - st.recvWin
					}
					st.recvWin += grow
					credit += grow
				}
				st.lastCred = now
			}
			st.mu.Unlock()
			if credit > 0 {
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], uint32(credit))
				_ = st.sess.writeFrame(cmdWND, st.id, b[:])
			}
			return n, nil
		}
		if st.err != nil {
			err := st.err
			st.mu.Unlock()
			return 0, err
		}
		if st.finRecv {
			st.mu.Unlock()
			return 0, io.EOF
		}
		st.mu.Unlock()
		select {
		case <-st.readable:
		case <-st.sess.closed:
			st.fail(ErrClosed)
		}
	}
}

// Write implements io.Writer.
func (st *Stream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		st.mu.Lock()
		if st.err != nil {
			err := st.err
			st.mu.Unlock()
			return written, err
		}
		if st.finSent {
			st.mu.Unlock()
			return written, io.ErrClosedPipe
		}
		if st.sendCred <= 0 {
			st.mu.Unlock()
			select {
			case <-st.writable:
			case <-st.sess.closed:
				st.fail(ErrClosed)
			}
			continue
		}
		n := len(p)
		if n > maxData {
			n = maxData
		}
		if int64(n) > st.sendCred {
			n = int(st.sendCred)
		}
		st.sendCred -= int64(n)
		st.mu.Unlock()
		if err := st.sess.writeFrame(cmdDATA, st.id, p[:n]); err != nil {
			st.fail(err)
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite sends FIN (half-close).
func (st *Stream) CloseWrite() error {
	st.mu.Lock()
	if st.finSent || st.err != nil {
		st.mu.Unlock()
		return nil
	}
	st.finSent = true
	done := st.finRecv
	st.mu.Unlock()
	err := st.sess.writeFrame(cmdFIN, st.id, nil)
	if done {
		st.sess.remove(st.id)
	}
	return err
}

// Close fully closes the stream. If the peer has not finished sending, the
// stream is reset.
func (st *Stream) Close() error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	graceful := st.finRecv && st.err == nil
	hadErr := st.err != nil
	st.mu.Unlock()
	if graceful {
		err := st.CloseWrite()
		st.sess.remove(st.id)
		return err
	}
	st.sess.remove(st.id)
	if !hadErr {
		_ = st.sess.writeFrame(cmdRST, st.id, nil)
	}
	st.fail(ErrReset)
	return nil
}

// Reset aborts the stream immediately.
func (st *Stream) Reset() {
	st.mu.Lock()
	hadErr := st.err != nil
	st.closed = true
	st.mu.Unlock()
	st.sess.remove(st.id)
	if !hadErr {
		_ = st.sess.writeFrame(cmdRST, st.id, nil)
	}
	st.fail(ErrReset)
}

// Session returns the owning session.
func (st *Stream) Session() *Session { return st.sess }
