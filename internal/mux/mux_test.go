package mux

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func sessions(t *testing.T) (*Session, *Session) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return New(c, true, Config{}), New(<-ch, false, Config{})
}

func echoServer(s *Session) {
	for {
		st, err := s.Accept()
		if err != nil {
			return
		}
		st.Accept(true)
		go func() {
			io.Copy(st, st)
			st.CloseWrite()
			st.Close()
		}()
	}
}

func TestManyStreams(t *testing.T) {
	c, s := sessions(t)
	defer c.Close()
	defer s.Close()
	go echoServer(s)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := c.Open("x")
			if err != nil {
				t.Error(err)
				return
			}
			if err := st.WaitConnected(5 * time.Second); err != nil {
				t.Error(err)
				return
			}
			data := make([]byte, 1<<20+123)
			rand.Read(data)
			go func() { st.Write(data); st.CloseWrite() }()
			got, err := io.ReadAll(st)
			if err != nil || !bytes.Equal(got, data) {
				t.Errorf("echo mismatch err=%v len=%d", err, len(got))
			}
			st.Close()
		}()
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	if n := c.NumStreams(); n != 0 {
		t.Fatalf("leaked %d client streams", n)
	}
	if n := s.NumStreams(); n != 0 {
		t.Fatalf("leaked %d server streams", n)
	}
}

// A stalled reader on one stream must not block another stream.
func TestNoHeadOfLineBlocking(t *testing.T) {
	c, s := sessions(t)
	defer c.Close()
	defer s.Close()
	got := make(chan *Stream, 2)
	go func() {
		for {
			st, err := s.Accept()
			if err != nil {
				return
			}
			st.Accept(true)
			got <- st
		}
	}()
	slow, _ := c.Open("slow")
	<-got // never read from it
	go slow.Write(make([]byte, 3*InitialWindow))
	time.Sleep(200 * time.Millisecond)
	fast, _ := c.Open("fast")
	fs := <-got
	go fast.Write([]byte("ping"))
	buf := make([]byte, 4)
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(fs, buf); done <- err }()
	select {
	case err := <-done:
		if err != nil || string(buf) != "ping" {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fast stream blocked by slow stream")
	}
}

func TestRefuseAndReset(t *testing.T) {
	c, s := sessions(t)
	defer c.Close()
	defer s.Close()
	go func() {
		st, _ := s.Accept()
		st.Accept(false)
	}()
	st, _ := c.Open("nope")
	if err := st.WaitConnected(3 * time.Second); err != ErrRefused {
		t.Fatalf("want refused got %v", err)
	}
}

func TestSessionDeathUnblocks(t *testing.T) {
	c, s := sessions(t)
	go func() {
		st, _ := s.Accept()
		st.Accept(true)
	}()
	st, _ := c.Open("x")
	st.WaitConnected(3 * time.Second)
	done := make(chan error, 1)
	go func() { _, err := st.Read(make([]byte, 10)); done <- err }()
	time.Sleep(50 * time.Millisecond)
	s.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read not unblocked")
	}
	c.Close()
}

func TestRTT(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	cn, _ := net.Dial("tcp", ln.Addr().String())
	cfg := Config{PingInterval: 50 * time.Millisecond}
	c := New(cn, true, cfg)
	s := New(<-ch, false, cfg)
	defer c.Close()
	defer s.Close()
	time.Sleep(300 * time.Millisecond)
	if c.RTT() == 0 {
		t.Fatal("rtt not measured")
	}
}
