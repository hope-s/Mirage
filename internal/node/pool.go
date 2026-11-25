package node

import (
	"errors"
	"log"
	mrand "math/rand/v2"
	"sort"
	"sync"
	"time"

	"mirage/internal/mux"
)

type logger struct{ debug bool }

func (l *logger) infof(f string, a ...any) { log.Printf(f, a...) }
func (l *logger) debugf(f string, a ...any) {
	if l.debug {
		log.Printf(f, a...)
	}
}

// sessInfo describes a live tunnel session.
type sessInfo struct {
	Link      string
	Transport string
	Remote    string
	Backup    bool
	Dialed    bool
	Cipher    string
}

// Pool holds the iran node's live sessions and picks one per new stream.
// Selection prefers non-backup links, then the lowest cost where
// cost = smoothed RTT + a penalty per active stream (least-loaded).
type Pool struct {
	mu      sync.Mutex
	sess    map[*mux.Session]sessInfo
	changed chan struct{}
}

func newPool() *Pool {
	return &Pool{sess: map[*mux.Session]sessInfo{}, changed: make(chan struct{})}
}

func (p *Pool) add(s *mux.Session, info sessInfo) {
	p.mu.Lock()
	p.sess[s] = info
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	go func() {
		<-s.Done()
		p.mu.Lock()
		delete(p.sess, s)
		p.mu.Unlock()
	}()
}

func cost(s *mux.Session) float64 {
	rtt := s.RTT()
	if rtt == 0 {
		rtt = 300 * time.Millisecond
	}
	return float64(rtt.Milliseconds()) + 8*float64(s.NumStreams())
}

func (p *Pool) candidates(exclude map[*mux.Session]bool) []*mux.Session {
	p.mu.Lock()
	defer p.mu.Unlock()
	var primary, backup []*mux.Session
	for s, info := range p.sess {
		if exclude[s] || s.IsClosed() || s.Draining() {
			continue
		}
		if info.Backup {
			backup = append(backup, s)
		} else {
			primary = append(primary, s)
		}
	}
	list := primary
	if len(list) == 0 {
		list = backup
	}
	// shuffle first so equal costs are spread evenly
	mrand.Shuffle(len(list), func(i, j int) { list[i], list[j] = list[j], list[i] })
	sort.SliceStable(list, func(i, j int) bool { return cost(list[i]) < cost(list[j]) })
	return list
}

func (p *Pool) waitChange(d time.Duration) {
	p.mu.Lock()
	ch := p.changed
	p.mu.Unlock()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch:
	case <-t.C:
	}
}

var errNoTunnel = errors.New("no tunnel connection available")

// Open opens a stream to target through the best session, failing over to
// other sessions if one turns out to be dead.
func (p *Pool) Open(target string) (*mux.Stream, error) {
	exclude := map[*mux.Session]bool{}
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error = errNoTunnel
	for attempt := 0; attempt < 4 && time.Now().Before(deadline); {
		list := p.candidates(exclude)
		if len(list) == 0 {
			if len(exclude) > 0 {
				// every session failed once; give reconnects a moment,
				// then allow retrying any session
				p.waitChange(min(2*time.Second, time.Until(deadline)))
				exclude = map[*mux.Session]bool{}
				continue
			}
			p.waitChange(time.Until(deadline))
			if len(p.candidates(nil)) == 0 {
				break
			}
			continue
		}
		s := list[0]
		attempt++
		st, err := s.Open(target)
		if err != nil {
			exclude[s] = true
			lastErr = err
			continue
		}
		err = st.WaitConnected(15 * time.Second)
		if err == nil {
			return st, nil
		}
		if errors.Is(err, mux.ErrRefused) {
			return nil, err // the destination itself is unreachable
		}
		if errors.Is(err, mux.ErrTimeout) {
			// no answer at all: the connection is silently dead
			// (blackholed); drop it so a fresh one is dialed now
			// instead of waiting for keepalive to notice.
			s.Close()
		}
		exclude[s] = true
		lastErr = err
	}
	return nil, lastErr
}

// snapshot is used by the status endpoint.
func (p *Pool) snapshot() map[*mux.Session]sessInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[*mux.Session]sessInfo, len(p.sess))
	for k, v := range p.sess {
		out[k] = v
	}
	return out
}
